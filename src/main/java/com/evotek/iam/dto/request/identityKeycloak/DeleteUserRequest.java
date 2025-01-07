package com.evotek.iam.dto.request.identityKeycloak;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DeleteUserRequest {
    private String deletedBody;
}
