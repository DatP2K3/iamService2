package com.evotek.iam.dto.request.identityKeycloak;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ResetPasswordRequest {
    private String type;
    private String value;
    private boolean temporary;
}
