package com.evotek.iam.configuration;

import com.evotek.iam.service.self_idp.SelfIDPAuthService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.*;

import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

@Configuration
public class CustomJwtDecoderConfig {
    @Bean("selfIdpDecoder")
    @ConditionalOnProperty(name = "auth.keycloak-enabled", havingValue = "false")
    public JwtDecoder customJwtDecoderSelfIDP(SelfIDPAuthService authService, TokenProvider tokenProvider) {
        return new JwtDecoder() {
            private NimbusJwtDecoder nimbusJwtDecoder = null;

            @Override
            public Jwt decode(String token) throws JwtException {
                var isValid = authService.introspect(token);

                if (!isValid) {
                    throw new JwtException("Token invalid");
                }

                if (Objects.isNull(nimbusJwtDecoder)) {
                    try {
                        nimbusJwtDecoder = NimbusJwtDecoder.withPublicKey(
                                (RSAPublicKey) tokenProvider.getKeyPair().getPublic()
                        ).build();
                    } catch (Exception e) {
                        throw new JwtException("Failed to initialize NimbusJwtDecoder: " + e.getMessage());
                    }
                }

                try {
                    return nimbusJwtDecoder.decode(token);
                } catch (JwtException e) {
                    throw new JwtException("JWT decoding failed: " + e.getMessage(), e);
                }
            }
        };
    }

    @Bean("keycloakDecoder")
    @ConditionalOnProperty(name = "auth.keycloak-enabled", havingValue = "true")
    public JwtDecoder keycloakJwtDecoder(@Value("${security.oauth2.resourceserver.jwt.issuer-uri}") String issuerUri) {
        return JwtDecoders.fromIssuerLocation(issuerUri);
    }
}