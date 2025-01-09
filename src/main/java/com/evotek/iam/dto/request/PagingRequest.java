package com.evotek.iam.dto.request;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class PagingRequest {
    @Min(value = 1, message = "Page index must be greater than 0")
    @Max(value = 1000, message = "Page index be less than 1000")
    @Builder.Default protected int pageIndex = 1;

    @Min(value = 1, message = "Page size must be greater than 0")
    @Max(value = 500, message = "Page size must be less than or equal to 500")
    @Builder.Default protected int pageSize = 30;

    protected String sortBy;
}
