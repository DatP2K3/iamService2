package com.evotek.iam.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.*;
import lombok.experimental.SuperBuilder;

@Getter
@Setter
@JsonInclude(JsonInclude.Include.NON_NULL)
@SuperBuilder
public class PageApiResponse<T> extends ApiResponses<T> {
    private PageableResponse pageable;

    @Data
    @Builder
    public static class PageableResponse {
        private int pageIndex;
        private int pageSize;
    }
}