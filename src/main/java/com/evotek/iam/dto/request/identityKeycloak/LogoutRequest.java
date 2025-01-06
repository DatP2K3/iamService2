package com.evotek.iam.dto.request.identityKeycloak;

import lombok.*;
import lombok.experimental.FieldDefaults;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LogoutRequest {
    private String client_id;
    private String client_secret;
    private String refresh_token;
}
