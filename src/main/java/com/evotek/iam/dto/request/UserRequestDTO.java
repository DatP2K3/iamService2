package com.evotek.iam.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.hibernate.validator.constraints.URL;

@Data
@AllArgsConstructor
@NoArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class UserRequestDTO {
    int id;
    @NotBlank(message = "Full name cannot be blank")
    String fullName;
    @NotBlank(message = "Birth date cannot be blank")
    String birthDate;
    @NotBlank(message = "Phone cannot be blank")
    @Pattern(regexp = "^\\+?[0-9]{10,11}$", message = "Phone must be a valid phone number")
    String phone;
    @NotBlank(message = "Email cannot be blank")
    String email;
    @NotBlank(message = "Password cannot be blank")
    @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@#$%^&-+=()!?\"]).{8,128}$", message = "Password must be at least 8 characters long and contain at least one letter and one number one special character and one uppercase letter")
    String password;
    @NotBlank(message = "Avatar cannot be blank")
    @URL(message = "Avatar must be a valid URL")
    String avatar;
    @NotNull(message = "Role cannot be null")
    int roleId;
}
