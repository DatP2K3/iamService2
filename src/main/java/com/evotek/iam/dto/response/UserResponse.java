package com.evotek.iam.dto.response;

import lombok.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserResponse {
    private int selfUserID;
    private String keyCloakUserID;
    private String email;
    private String username;
    private String firstName;
    private String lastName;
}