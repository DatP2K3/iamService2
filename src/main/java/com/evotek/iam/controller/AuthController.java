package com.evotek.iam.controller;

import com.evotek.iam.dto.ApiResponse;
import com.evotek.iam.dto.request.LoginRequest;
import com.evotek.iam.dto.request.PasswordRequestDTO;
import com.evotek.iam.dto.request.VerifyOtpRequestDTO;
import com.evotek.iam.dto.request.identityKeycloak.ResetPasswordRequest;
import com.evotek.iam.dto.response.TokenResponse;
import com.evotek.iam.service.ServiceStrategy;
import com.evotek.iam.service.common.AuthService2;
import com.evotek.iam.service.self_idp.SelfIDPAuthService;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private String typeAuthService ="keycloak_auth_service";
    @Value("${auth.keycloak-enabled}")
    private boolean keycloakEnabled;
    private final ServiceStrategy serviceStrategy;
    private AuthService2 authService2;

    @PostConstruct
    public void init() {
        if (!keycloakEnabled) {
            this.typeAuthService = "self_idp_auth_service";
        }
        this.authService2 = serviceStrategy.getAuthService(typeAuthService);
    }

    @PostMapping("/login_iam")
    public ApiResponse<TokenResponse> loginIam(@RequestBody LoginRequest loginRequest) {
        TokenResponse tokenResponse = authService2.authenticate(loginRequest);
        return ApiResponse.<TokenResponse>builder()
                .data(tokenResponse)
                .success(true)
                .code(201)
                .message(keycloakEnabled?"Login successfully":"OTP sent to your Email")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
    }

    @PostMapping("/verify-otp")
    public ApiResponse<TokenResponse> verifyOtp(@RequestBody VerifyOtpRequestDTO verifyOtpRequestDTO) {
        TokenResponse result = ((SelfIDPAuthService) authService2).verifyOtp(verifyOtpRequestDTO);
        return ApiResponse.<TokenResponse>builder()
                .data(result)
                .success(true)
                .code(200)
                .message("OTP đã được xác nhận thành công")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
    }

    @PostMapping("/logout-user")
    ApiResponse<String> logoutIam(HttpServletRequest request, @RequestParam("refreshToken") String refreshToken) {
        authService2.logoutIam(request, refreshToken);
        return ApiResponse.<String>builder()
                .data("Logout successful")
                .success(true)
                .code(200)
                .message("Logout successful")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
    }

    @PostMapping("/refresh")
    ApiResponse<TokenResponse> refresh(@RequestParam("refreshToken") String refreshToken) {
        TokenResponse tokenResponse = authService2.refresh(refreshToken);
        return ApiResponse.<TokenResponse>builder()
                .data(tokenResponse)
                .success(true)
                .code(200)
                .message("Refresh Token successful")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
    }

    @PostMapping("/forgot-password")
    public ApiResponse<Void> requestPasswordReset(@RequestParam String username, @RequestBody(required = false) ResetPasswordRequest resetPasswordRequest) {
        authService2.requestPasswordReset(username, resetPasswordRequest);
        return ApiResponse.<Void>builder()
                .success(true)
                .code(200)
                .message(keycloakEnabled?"Password successfully reset":"Reset password link sent to email")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
    }

    @PatchMapping("/reset-password")
    public ApiResponse<Void> resetPassword(@RequestParam String token, @RequestBody ResetPasswordRequest resetPasswordRequest) {
        authService2.resetPassword(token, resetPasswordRequest);
        return ApiResponse.<Void>builder()
                .success(true)
                .code(200)
                .message("Password successfully reset")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
    }
}
