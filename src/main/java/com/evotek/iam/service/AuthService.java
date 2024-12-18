package com.evotek.iam.service;

import com.evotek.iam.configuration.TokenProvider;
import com.evotek.iam.dto.request.*;
import com.evotek.iam.dto.response.AuthenticationResponseDTO;
import com.evotek.iam.dto.response.IntrospectResponseDTO;
import com.evotek.iam.exception.ErrorCode;
import com.evotek.iam.exception.ResourceNotFoundException;
import com.evotek.iam.model.InvalidatedToken;
import com.evotek.iam.model.Role;
import com.evotek.iam.model.User;
import com.evotek.iam.model.UserActivityLog;
import com.evotek.iam.repository.InvalidatedTokenRepository;
import com.evotek.iam.repository.UserActivityLogRepository;
import com.evotek.iam.repository.UserRepository;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.evotek.iam.exception.AuthException;
import jakarta.servlet.http.HttpServletRequest;
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
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;
//Áp Dụng lưu token ko hợp lệ vào redis, thời gia tương ứng với thời gian hết hạn của token
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final InvalidatedTokenRepository invalidatedTokenRepository;
    private final EmailService emailService;
    private final RedisTemplate redisTemplate;
    private final UserActivityLogRepository userActivityLogRepository;
    private final TokenProvider tokenProvider;

//    @Value("${jwt.private-key}")
//    private String PRIVATE_KEY;
//
//    @Value("${jwt.public-key}")
//    private String PUBLIC_KEY;

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

        UserActivityLog log = new UserActivityLog();
        log.setUserId(user.getId());
        log.setActivity("Login");
        log.setCreatedAt(LocalDateTime.now());
        userActivityLogRepository.save(log);

        return AuthenticationResponseDTO.builder().token(token).authenticated(true).build();
    }

    public void logout(HttpServletRequest request) throws ParseException, JOSEException {
        try {
            String token = request.getHeader("Authorization");
            if (token != null && token.startsWith("Bearer ")) {
                token = token.substring(7);
            }

            var signToken = verifyToken(token, true);

            String jit = signToken.getJWTClaimsSet().getJWTID();
            Date expiryTime = signToken.getJWTClaimsSet().getExpirationTime();

            InvalidatedToken invalidatedToken =
                    InvalidatedToken.builder().id(jit).expiryTime(expiryTime).build();

            invalidatedTokenRepository.save(invalidatedToken);

            UserActivityLog log = new UserActivityLog();
            log.setUserId(signToken.getJWTClaimsSet().getIntegerClaim("userId"));
            log.setActivity("Logout");
            log.setCreatedAt(LocalDateTime.now());
            userActivityLogRepository.save(log);
        } catch (AuthException exception) {
            log.info("Token already expired");
        }
    }

    public AuthenticationResponseDTO refreshToken(HttpServletRequest request) throws ParseException, JOSEException {
        String oldToken = request.getHeader("Authorization");
        if (oldToken != null && oldToken.startsWith("Bearer ")) {
            oldToken = oldToken.substring(7);
        }

        var signedJWT = verifyToken(oldToken, true);

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
        JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) tokenProvider.getKeyPair().getPublic());
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
                .claim("userId", user.getId())
                .build();

        Payload payload = new Payload(jwtClaimsSet.toJSONObject());

        JWSObject jwsObject = new JWSObject(header, payload);

        RSASSASigner signer = new RSASSASigner(tokenProvider.getKeyPair().getPrivate());

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
            emailService.sendMailAlert(email, "change_password");

            UserActivityLog log = new UserActivityLog();
            log.setUserId(user.getId());
            log.setActivity("Reset PassWord");
            log.setCreatedAt(LocalDateTime.now());
            userActivityLogRepository.save(log);

        } catch (AuthException ex) {
            throw new AuthException(ErrorCode.INVALID_KEY);
        } catch (Exception ex) {
            throw new AuthException(ErrorCode.UNCATEGORIZED_EXCEPTION);
        }
    }
}

