package com.evotek.iam.dto.request.identityKeycloak;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonIgnoreProperties(value = {"type", "temporary"}, allowSetters = true)
public class ResetPasswordRequest {
    private String type = "password";
    private String value;
    private boolean temporary = false;
}
