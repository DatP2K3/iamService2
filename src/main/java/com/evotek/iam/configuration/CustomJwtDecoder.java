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
    @Value("${jwt.public-key}")
    private String PUBLIC_KEY;

    private final AuthService authService;

    private NimbusJwtDecoder nimbusJwtDecoder = null;

    @Override
    public Jwt decode(String token) throws JwtException {

        // Kiểm tra tính hợp lệ của token
        try {
            var response = authService.introspect(
                    IntrospectRequestDTO.builder().token(token).build());

            if (!response.isValid()) throw new JwtException("Token invalid");
        } catch (JOSEException | ParseException e) {
            throw new JwtException(e.getMessage());
        }

        // Nếu chưa khởi tạo nimbusJwtDecoder, khởi tạo nó với khóa công khai RSA
        if (Objects.isNull(nimbusJwtDecoder)) {
            RSAPublicKey publicKey = null;

            try {
                //Chuyển PUBLIC_KEY từ Base64 thành mảng byte
                byte[] publicKeyBytes = Base64.getDecoder().decode(PUBLIC_KEY);

                // Sử dụng KeyFactory để tạo RSAPublicKey từ mảng byte
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
                publicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);
                nimbusJwtDecoder = NimbusJwtDecoder.withPublicKey(publicKey)
                        .build();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new RuntimeException("Error creating RSAPublicKey from Base64", e);
            } catch (Exception e) {
                throw new JwtException("Failed to initialize JWT decoder with public key", e);
            }
        }

        return nimbusJwtDecoder.decode(token);
    }
}