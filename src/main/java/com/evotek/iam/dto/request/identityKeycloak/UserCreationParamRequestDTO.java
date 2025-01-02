package com.evotek.iam.dto.request.identityKeycloak;

import lombok.*;
import lombok.experimental.FieldDefaults;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class UserCreationParamRequestDTO {
    String username;
    boolean enabled;
    String email;
    boolean emailVerified;
    String firstName;
    String lastName;
    List<CredentialRequestDTO> credentials;
}
