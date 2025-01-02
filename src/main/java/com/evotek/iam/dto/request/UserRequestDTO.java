package com.evotek.iam.dto.request;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.*;
import lombok.experimental.FieldDefaults;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
@Table(name = "users")
public class UserRequestDTO {
    @NotBlank(message = "UserName cannot be blank")
    String username;

    @NotBlank(message = "Password cannot be blank")
    @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@#$%^&-+=()!?\"]).{8,128}$", message = "Password must be at least 8 characters long and contain at least one letter and one number one special character and one uppercase letter")
    String password;

    @NotBlank(message = "Email cannot be blank")
    String email;

    @NotBlank(message = "FirstName cannot be blank")
    String firstName;

    @NotBlank(message = "LastName cannot be blank")
    String lastName;

}