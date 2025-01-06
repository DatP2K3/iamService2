package com.evotek.iam.dto.request;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserSearchRequest {
    private String keyword;
    private int pageIndex;
    private int pageSize;
    private String sortBy;
}

