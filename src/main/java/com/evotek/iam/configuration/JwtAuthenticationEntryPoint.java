package com.evotek.iam.configuration;

import com.evotek.iam.dto.response.ApiResponses;
import com.evotek.iam.exception.ErrorCode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;

public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void commence(
            HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException {
        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            response.sendRedirect("/oauth2/authorization/google");
        } else {
            ErrorCode errorCode = ErrorCode.UNAUTHENTICATED;

            response.setStatus(errorCode.getStatusCode().value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);

            ApiResponses<?> apiResponses = ApiResponses.builder()
                    .code(errorCode.getCode())
                    .message(errorCode.getMessage())
                    .success(false)
                    .timestamp(System.currentTimeMillis())
                    .status("error")
                    .build();

            response.getWriter().write(objectMapper.writeValueAsString(apiResponses));
            response.flushBuffer();
        }
    }
}