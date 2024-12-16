package com.evotek.iam.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;

@Data
@AllArgsConstructor
@NoArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class UserInforRequestDTO {
    @NotBlank(message = "Full name cannot be blank")
    String fullName;
    @NotBlank(message = "Birth date cannot be blank")
    String birthDate;
    @NotBlank(message = "Phone cannot be blank")
    @Pattern(regexp = "^\\+?[0-9]{10,11}$", message = "Phone must be a valid phone number")
    String phone;
    @NotBlank(message = "Address cannot be blank")
    String address;
}
