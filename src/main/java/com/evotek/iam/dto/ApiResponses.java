package com.evotek.iam.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;

import java.io.Serializable;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Builder
@Data
public class ApiResponses<T> implements Serializable {
    protected T data;
    private boolean success;
    private int code;
    private String message;
    private long timestamp;
    private String status;
}