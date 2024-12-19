package com.evotek.iam.configuration;

import com.evotek.iam.dto.request.IntrospectRequestDTO;
import com.evotek.iam.service.AuthService;
import com.nimbusds.jose.JOSEException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.Objects;

@Component
@RequiredArgsConstructor
public class CustomJwtDecoder implements JwtDecoder {
//    @Value("${jwt.public-key}")
//    private String PUBLIC_KEY;
    private final AuthService authService;
    private NimbusJwtDecoder nimbusJwtDecoder = null;
    private final TokenProvider tokenProvider;

    @Override
    public Jwt decode(String token) throws JwtException {

        try {
            var response = authService.introspect(
                    IntrospectRequestDTO.builder().token(token).build());

            if (!response.isValid()) throw new JwtException("Token invalid");
        } catch (JOSEException | ParseException e) {
            throw new JwtException(e.getMessage());
        }

        if (Objects.isNull(nimbusJwtDecoder)) {
            nimbusJwtDecoder = NimbusJwtDecoder.withPublicKey((RSAPublicKey) tokenProvider.getKeyPair().getPublic()).build();
        }

        return nimbusJwtDecoder.decode(token);
    }
}