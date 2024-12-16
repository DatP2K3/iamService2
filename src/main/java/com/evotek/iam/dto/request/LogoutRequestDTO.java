package com.evotek.iam.dto.request;

import lombok.*;
import lombok.experimental.FieldDefaults;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LogoutRequestDTO {
    private String token;
}