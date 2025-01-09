package com.evotek.iam.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.experimental.SuperBuilder;

import java.io.Serializable;

@JsonInclude(JsonInclude.Include.NON_NULL)
@SuperBuilder
@Data
public class ApiResponses<T> implements Serializable {
    private T data;
    private boolean success;
    private int code;
    private String message;
    private long timestamp;
    private String status;
}