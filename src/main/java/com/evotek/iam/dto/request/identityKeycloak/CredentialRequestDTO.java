package com.evotek.iam.dto.request.identityKeycloak;

import lombok.*;
import lombok.experimental.FieldDefaults;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CredentialRequestDTO {
    private String type;
    private String value;
    private boolean temporary;
}
