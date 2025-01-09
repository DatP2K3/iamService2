package com.evotek.iam.service.self_idp;

import com.evotek.iam.configuration.TokenProvider;
import com.evotek.iam.dto.request.LoginRequest;
import com.evotek.iam.dto.request.VerifyOtpRequest;
import com.evotek.iam.dto.request.identityKeycloak.ResetPasswordRequest;
import com.evotek.iam.dto.request.identityKeycloak.TokenRequest;
import com.evotek.iam.dto.response.TokenResponse;
import com.evotek.iam.exception.AppException;
import com.evotek.iam.exception.ErrorCode;
import com.evotek.iam.exception.ErrorNormalizer;
import com.evotek.iam.exception.ResourceNotFoundException;
import com.evotek.iam.model.User;
import com.evotek.iam.model.UserActivityLog;
import com.evotek.iam.repository.IdentityClient;
import com.evotek.iam.repository.UserRepository;
import com.evotek.iam.service.common.AuthService;
import com.evotek.iam.service.common.EmailService;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import feign.FeignException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Component("self_idp_auth_service")
@RequiredArgsConstructor
@Slf4j
public class SelfIDPAuthService implements AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final ErrorNormalizer errorNormalizer;
    private final RedisTemplate redisTemplate;
    private final TokenProvider tokenProvider;
    private final IdentityClient identityClient;

    @Value("${jwt.valid-duration}")
    private long VALID_DURATION;
    @Value("${jwt.refreshable-duration}")
    private long REFRESHABLE_DURATION;
    @Value("${idp.client-id}")
    private String clientId;
    @Value("${idp.client-secret}")
    private String clientSecret;


    public boolean introspect(String token) {
        boolean isValid = true;

        try {
            verifyToken(token);
        } catch (AppException e) {
            isValid = false;
        }

        return isValid;
    }
    @Override
    public TokenResponse authenticate(LoginRequest loginRequest) {
        User user = userRepository
                .findByUsername((loginRequest.getUsername())).orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
        boolean authenticated = passwordEncoder.matches(loginRequest.getPassword(), user.getPassword());

        if (!authenticated) throw new AppException(ErrorCode.UNAUTHENTICATED);

        SecureRandom random = new SecureRandom();
        int otp = random.nextInt(900000) + 100000;

        redisTemplate.opsForValue().set(String.valueOf(otp), user.getUsername(), 300, TimeUnit.SECONDS);

        emailService.sendMailOtp(user.getEmail(), String.valueOf(otp));
        return null;
    }

    public TokenResponse verifyOtp(VerifyOtpRequest verifyOtpRequest) {
        if (!redisTemplate.hasKey(verifyOtpRequest.getOtp())) {
            throw new AppException(ErrorCode.UNAUTHENTICATED);
        }
        if(!redisTemplate.opsForValue().get(verifyOtpRequest.getOtp()).equals(verifyOtpRequest.getUsername())){
            throw new AppException(ErrorCode.UNAUTHENTICATED);
        }

        User user = userRepository
                .findByUsername((verifyOtpRequest.getUsername())).orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));

        redisTemplate.delete(verifyOtpRequest.getOtp());

        var accessToken = generateToken(user, false, false);
        var refreshToken = generateToken(user, false, true);
        UserActivityLog log = new UserActivityLog();

        return TokenResponse.builder().accessToken(accessToken).refreshToken(refreshToken).build();
    }

    private String generateToken(User user, boolean isforgotPassword, boolean isRefresh) {
        JWSHeader header = new JWSHeader(JWSAlgorithm.RS256);

        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .subject(user.getUsername())
                .issuer("evotek.iam.com")
                .issueTime(new Date())
                .jwtID(UUID.randomUUID().toString())
                .claim("userId", user.getSelfUserID());


        if (!isRefresh) {
            Date expirationTime = new Date(Instant.now().plus(VALID_DURATION, ChronoUnit.SECONDS).toEpochMilli());
            if(isforgotPassword){
                expirationTime = new Date(Instant.now().plus(15, ChronoUnit.MINUTES).toEpochMilli());
            }

//            claimsBuilder.claim("scope", buildScope(user));
            claimsBuilder.expirationTime(expirationTime);
        }
        JWTClaimsSet jwtClaimsSet = claimsBuilder.build();
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

    @Override
    public void logoutIam(HttpServletRequest request, String refreshToken) {
        try {
            String token = request.getHeader("Authorization");
            if (token != null && token.startsWith("Bearer ")) {
                token = token.substring(7);
            }

            var signedJWT_access = verifyToken(token);
            var access_jit = signedJWT_access.getJWTClaimsSet().getJWTID();
            var access_expiryTime = signedJWT_access.getJWTClaimsSet().getExpirationTime();
            var access_expiryTimeMillis = signedJWT_access.getJWTClaimsSet().getExpirationTime().getTime();
            long currentTimeMillis = System.currentTimeMillis();
            long access_remainingTimeMillis = access_expiryTimeMillis - currentTimeMillis;
            var signedJWT_refresh = verifyToken(refreshToken);
            var refresh_jit = signedJWT_refresh.getJWTClaimsSet().getJWTID();
            long refresh_remainingTimeMillis = currentTimeMillis + REFRESHABLE_DURATION * 1000;
            var refresh_expiryTime = new Date(refresh_remainingTimeMillis);

            redisTemplate.opsForValue().set(access_jit, access_expiryTime, access_remainingTimeMillis, TimeUnit.MILLISECONDS);
            redisTemplate.opsForValue().set(refresh_jit, refresh_expiryTime, refresh_remainingTimeMillis, TimeUnit.MILLISECONDS);

            UserActivityLog log = new UserActivityLog();
            log.setUserId(signedJWT_access.getJWTClaimsSet().getIntegerClaim("userId"));
            log.setActivity("Logout");
            log.setCreatedAt(LocalDateTime.now());
        } catch (FeignException exception) {
            throw errorNormalizer.handleKeyCloakException(exception);
        } catch (ParseException e) {
            throw new AppException(ErrorCode.INVALID_TOKEN);
        }
    }

    @Override
    public TokenResponse refresh(String refreshToken) {
        try {
            var signedJWT = verifyToken(refreshToken);
            var username = signedJWT.getJWTClaimsSet().getSubject();
            var user = userRepository.findByUsername(username).orElseThrow(() -> new AppException(ErrorCode.UNAUTHENTICATED));
            var accessToken = generateToken(user, false, false);

            return TokenResponse.builder().accessToken(accessToken).refreshToken(refreshToken).build();
        } catch (ParseException e) {
            throw new AppException(ErrorCode.INVALID_TOKEN);
        }
    }

    @Override
    public void requestPasswordReset(String username, ResetPasswordRequest resetPasswordRequest) {
        try {
            User user = userRepository
                    .findByUsername(username)
                    .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
            String token = generateToken(user, true, false);

            String resetLink = "http://127.0.0.1:5500/resetPassword.html?token=" + token;

            emailService.sendMailForResetPassWord(user.getEmail(), resetLink);
        } catch (ResourceNotFoundException ex) {
            throw new AppException(ErrorCode.USER_NOT_EXISTED);
        } catch (Exception ex) {
            throw new AppException(ErrorCode.UNCATEGORIZED_EXCEPTION);
        }
    }

    private SignedJWT verifyToken(String token) {
        try {
            JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) tokenProvider.getKeyPair().getPublic());
            SignedJWT signedJWT = SignedJWT.parse(token);
            Date expiryTime = (signedJWT.getJWTClaimsSet().getExpirationTime() == null)
                    ? new Date(signedJWT
                    .getJWTClaimsSet()
                    .getIssueTime()
                    .toInstant()
                    .plus(REFRESHABLE_DURATION, ChronoUnit.SECONDS)
                    .toEpochMilli())
                    : signedJWT.getJWTClaimsSet().getExpirationTime();

            var verified = signedJWT.verify(verifier);

            if (!(verified && expiryTime.after(new Date()))) throw new AppException(ErrorCode.UNAUTHENTICATED);

            if (redisTemplate.hasKey(signedJWT.getJWTClaimsSet().getJWTID())) {
                throw new AppException(ErrorCode.UNAUTHENTICATED);
            }
            return signedJWT;
        } catch (ParseException | JOSEException e) {
            throw new AppException(ErrorCode.INVALID_TOKEN);
        }
    }

    public void resetPassword(String token, ResetPasswordRequest resetPasswordRequest) {
        try {
            SignedJWT signedJWT = verifyToken(token);
            String username = signedJWT.getJWTClaimsSet().getSubject();
            User user = userRepository.findByUsername(username).orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
            user.setPassword(passwordEncoder.encode(resetPasswordRequest.getValue()));
            userRepository.save(user);
            emailService.sendMailAlert(user.getEmail(), "change_password");

            var keycloakToken = identityClient.getToken(TokenRequest.builder()
                    .grant_type("client_credentials")
                    .client_id(clientId)
                    .client_secret(clientSecret)
                    .scope("openid")
                    .build());

            identityClient.resetPassword("Bearer " + keycloakToken.getAccessToken(), user.getProviderId(), resetPasswordRequest);

            UserActivityLog log = new UserActivityLog();
            log.setUserId(signedJWT.getJWTClaimsSet().getIntegerClaim("userId"));
            log.setActivity("Reset password");
            log.setCreatedAt(LocalDateTime.now());

        } catch (AppException ex) {
            throw new AppException(ErrorCode.INVALID_KEY);
        } catch (Exception ex) {
            throw new AppException(ErrorCode.UNCATEGORIZED_EXCEPTION);
        }
    }
}
