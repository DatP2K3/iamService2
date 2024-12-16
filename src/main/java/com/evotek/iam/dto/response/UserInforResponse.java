package com.evotek.iam.dto.response;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserInforResponse {
    private int id;
    private String fullName;
    private String birthDate;
    private String phone;
    private String address;
}
