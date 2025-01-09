package com.evotek.iam.dto.request;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UserSearchRequest extends PagingRequest {
    private String keyword;
}

