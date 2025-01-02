package com.evotek.iam.dto.response;

import lombok.*;
import lombok.experimental.FieldDefaults;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserResponseDTO {
    int selfUserID;
    String keyCloakUserID;
    String email;
    String username;
    String firstName;
    String lastName;
}
