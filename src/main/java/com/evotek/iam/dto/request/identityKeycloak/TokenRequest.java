package com.evotek.iam.dto.request.identityKeycloak;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TokenRequest {
    private String grant_type;
    private String client_id;
    private String client_secret;
    private String scope;
    private String username;
    private String password;
}
