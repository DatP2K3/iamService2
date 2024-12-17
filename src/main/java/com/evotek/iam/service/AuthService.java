package com.evotek.iam.service;

import com.evotek.iam.dto.request.*;
import com.evotek.iam.dto.response.AuthenticationResponseDTO;
import com.evotek.iam.dto.response.IntrospectResponseDTO;
import com.evotek.iam.exception.ErrorCode;
import com.evotek.iam.exception.ResourceNotFoundException;
import com.evotek.iam.model.InvalidatedToken;
import com.evotek.iam.model.Role;
import com.evotek.iam.model.User;
import com.evotek.iam.repository.InvalidatedTokenRepository;
import com.evotek.iam.repository.UserRepository;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.evotek.iam.exception.AuthException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final InvalidatedTokenRepository invalidatedTokenRepository;
    private final EmailService emailService;
    private final RedisTemplate redisTemplate;

    @Value("${jwt.private-key}")
    private String PRIVATE_KEY;

    @Value("${jwt.public-key}")
    private String PUBLIC_KEY;

    @Value("${jwt.valid-duration}")
    private long VALID_DURATION;

    @Value("${jwt.refreshable-duration}")
    private long REFRESHABLE_DURATION;

    public IntrospectResponseDTO introspect(IntrospectRequestDTO request) throws JOSEException, ParseException {
        var token = request.getToken();
        boolean isValid = true;

        try {
            verifyToken(token, false);
        } catch (AuthException e) {
            isValid = false;
        }

        return IntrospectResponseDTO.builder().valid(isValid).build();
    }

    public void authenticate(AuthenticationRequestDTO request) {
        var user = userRepository
                .findByEmail(request.getUsername())
                .orElseThrow(() -> new AuthException(ErrorCode.USER_NOT_EXISTED));
        boolean authenticated = passwordEncoder.matches(request.getPassword(), user.getPassword());

        if (!authenticated) throw new AuthException(ErrorCode.UNAUTHENTICATED);

        SecureRandom random = new SecureRandom();
        int otp = random.nextInt(900000) + 100000;

        redisTemplate.opsForValue().set(String.valueOf(otp), user.getEmail());

        emailService.sendMailOtp(user.getEmail(), String.valueOf(otp));
    }

    public AuthenticationResponseDTO verifyOtp(VerifyOtpRequestDTO verifyOtpRequestDTO) {
        if (!redisTemplate.hasKey(verifyOtpRequestDTO.getOtp())) {
            throw new AuthException(ErrorCode.UNAUTHENTICATED);
        }
        if(!redisTemplate.opsForValue().get(verifyOtpRequestDTO.getOtp()).equals(verifyOtpRequestDTO.getEmail())){
            throw new AuthException(ErrorCode.UNAUTHENTICATED);
        }

        User user = userRepository
                .findByEmail(redisTemplate.opsForValue().get(verifyOtpRequestDTO.getOtp()).toString())
                .orElseThrow(() -> new AuthException(ErrorCode.USER_NOT_EXISTED));

        redisTemplate.delete(verifyOtpRequestDTO.getOtp());

        var token = generateToken(user, false);

        return AuthenticationResponseDTO.builder().token(token).authenticated(true).build();
    }

    public void logout(LogoutRequestDTO request) throws ParseException, JOSEException {
        try {
            var signToken = verifyToken(request.getToken(), true);

            String jit = signToken.getJWTClaimsSet().getJWTID();
            Date expiryTime = signToken.getJWTClaimsSet().getExpirationTime();

            InvalidatedToken invalidatedToken =
                    InvalidatedToken.builder().id(jit).expiryTime(expiryTime).build();

            invalidatedTokenRepository.save(invalidatedToken);
        } catch (AuthException exception) {
            log.info("Token already expired");
        }
    }

    public AuthenticationResponseDTO refreshToken(RefreshRequestDTO request) throws ParseException, JOSEException {
        var signedJWT = verifyToken(request.getToken(), true);

        var jit = signedJWT.getJWTClaimsSet().getJWTID();
        var expiryTime = signedJWT.getJWTClaimsSet().getExpirationTime();

        InvalidatedToken invalidatedToken =
                InvalidatedToken.builder().id(jit).expiryTime(expiryTime).build();

        invalidatedTokenRepository.save(invalidatedToken);

        var username = signedJWT.getJWTClaimsSet().getSubject();

        var user =
                userRepository.findByEmail(username).orElseThrow(() -> new AuthException(ErrorCode.UNAUTHENTICATED));

        var token = generateToken(user, false);

        return AuthenticationResponseDTO.builder().token(token).authenticated(true).build();
    }

    private SignedJWT verifyToken(String token, boolean isRefresh) throws JOSEException, ParseException{
        RSAPublicKey publicKey = null;
        try {
            byte[] publicKeyBytes = Base64.getDecoder().decode(PUBLIC_KEY);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            publicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Error creating RSAPublicKey from Base64", e);
        }
        JWSVerifier verifier = new RSASSAVerifier(publicKey);
        SignedJWT signedJWT = SignedJWT.parse(token);
        Date expiryTime = (isRefresh)
                ? new Date(signedJWT
                .getJWTClaimsSet()
                .getIssueTime()
                .toInstant()
                .plus(REFRESHABLE_DURATION, ChronoUnit.SECONDS)
                .toEpochMilli())
                : signedJWT.getJWTClaimsSet().getExpirationTime();

        var verified = signedJWT.verify(verifier);

        if (!(verified && expiryTime.after(new Date()))) throw new AuthException(ErrorCode.UNAUTHENTICATED);

        if (invalidatedTokenRepository.existsById(signedJWT.getJWTClaimsSet().getJWTID()))
            throw new AuthException(ErrorCode.UNAUTHENTICATED);
        return signedJWT;
    }

    private String generateToken(User user, boolean isforgotPassword) {
        JWSHeader header = new JWSHeader(JWSAlgorithm.RS256);
        Date expirationTime = new Date(Instant.now().plus(VALID_DURATION, ChronoUnit.SECONDS).toEpochMilli());
        if(isforgotPassword){
            expirationTime = new Date(Instant.now().plus(15, ChronoUnit.MINUTES).toEpochMilli());
        }
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(user.getEmail())
                .issuer("evotek.iam.com")
                .issueTime(new Date())
                .expirationTime(expirationTime)
                .jwtID(UUID.randomUUID().toString())
                .claim("scope", buildScope(user))
                .build();

        Payload payload = new Payload(jwtClaimsSet.toJSONObject());

        JWSObject jwsObject = new JWSObject(header, payload);

        RSAPrivateKey privateKey = null;
        try {
            byte[] decodedKey = Base64.getDecoder().decode(PRIVATE_KEY);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            privateKey = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Error creating RSAPublicKey from Base64", e);
        }

        RSASSASigner signer = new RSASSASigner(privateKey);

        try {
            jwsObject.sign(signer);
            return jwsObject.serialize();
        } catch (JOSEException e) {
            log.error("Cannot create token", e);
            throw new RuntimeException(e);
        }
    }

    private String buildScope(User user) {
        Role role = user.getRole();
        if (role == null) {
            return "";
        }
        StringBuilder scopeBuilder = new StringBuilder();
        scopeBuilder.append(role.getName());
        return scopeBuilder.toString();
    }

    public void requestPasswordReset(String email) {
        try {
            User user = userRepository
                    .findByEmail(email)
                    .orElseThrow(() -> new AuthException(ErrorCode.USER_NOT_EXISTED));
            String token = generateToken(user, true);

            String resetLink = "http://127.0.0.1:5500/resetPassword.html?token=" + token;

            emailService.sendMailForResetPassWord(email, resetLink);
        } catch (ResourceNotFoundException ex) {
            throw new AuthException(ErrorCode.USER_NOT_EXISTED);
        } catch (Exception ex) {
            throw new AuthException(ErrorCode.UNCATEGORIZED_EXCEPTION);
        }
    }

    public void resetPassword(String token, String newPassword){
        try {
            SignedJWT signedJWT = verifyToken(token, false);
            String email = signedJWT.getJWTClaimsSet().getSubject();
            User user = userRepository.findByEmail(email).orElseThrow(() -> new AuthException(ErrorCode.USER_NOT_EXISTED));
            user.setPassword(passwordEncoder.encode(newPassword));
            userRepository.save(user);
        } catch (AuthException ex) {
            throw new AuthException(ErrorCode.INVALID_KEY);
        } catch (Exception ex) {
            throw new AuthException(ErrorCode.UNCATEGORIZED_EXCEPTION);
        }
    }
}

