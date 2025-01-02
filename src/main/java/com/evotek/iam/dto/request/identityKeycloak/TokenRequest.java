package com.evotek.iam.dto.request.identityKeycloak;

import lombok.*;
import lombok.experimental.FieldDefaults;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class TokenRequest {
    String grant_type;
    String client_id;
    String client_secret;
    String scope;
    String username;
    String password;
}
