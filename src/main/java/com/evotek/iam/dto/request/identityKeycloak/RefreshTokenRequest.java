package com.evotek.iam.dto.request.identityKeycloak;

import lombok.*;
import lombok.experimental.FieldDefaults;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshTokenRequest {
    private String client_id;
    private String client_secret;
    private String grant_type;
    private String refresh_token;
}