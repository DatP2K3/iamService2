package com.evotek.iam.dto.request.identityKeycloak;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CredentialRequestDTO {
    private String type;
    private String value;
    private boolean temporary;
}
