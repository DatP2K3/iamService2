package com.evotek.iam.controller;

import com.evotek.iam.dto.ApiResponses;
import com.evotek.iam.dto.request.LoginRequest;
import com.evotek.iam.dto.request.UserRequest;
import com.evotek.iam.dto.request.VerifyOtpRequest;
import com.evotek.iam.dto.request.identityKeycloak.ResetPasswordRequest;
import com.evotek.iam.dto.response.TokenResponse;
import com.evotek.iam.service.ServiceStrategy;
import com.evotek.iam.service.common.AuthService;
import com.evotek.iam.service.self_idp.SelfIDPAuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
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
    private AuthService authService;

    @PostConstruct
    public void init() {
        if (!keycloakEnabled) {
            this.typeAuthService = "self_idp_auth_service";
        }
        this.authService = serviceStrategy.getAuthService(typeAuthService);
    }

    @Operation(summary = "Đăng nhập",
            description = "API này sẽ xác thực thông tin đăng nhập và chuyển sang xác thực 2 bước bằng mã Otp.",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Thông tin đăng nhập của người dùng",
                    required = true,
                    content = @io.swagger.v3.oas.annotations.media.Content(
                            schema = @Schema(implementation = LoginRequest.class)
                    )
            ),
            responses = {
                    @ApiResponse(responseCode = "201", description = "Gửi mã Otp thành công")
            })
    @PostMapping("/login_iam")
    public ApiResponses<TokenResponse> loginIam(@RequestBody LoginRequest loginRequest) {
        TokenResponse tokenResponse = authService.authenticate(loginRequest);
        return ApiResponses.<TokenResponse>builder()
                .data(tokenResponse)
                .success(true)
                .code(201)
                .message(keycloakEnabled?"Login successfully":"OTP sent to your Email")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
    }

    @Operation(summary = "Xác thực mã Otp",
            description = "API này sẽ xác thực mã Otp và trả về token.",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Thông tin xác thực Otp",
                    required = true,
                    content = @io.swagger.v3.oas.annotations.media.Content(
                            schema = @Schema(implementation = VerifyOtpRequest.class)
                    )
            ),
            responses = {
                    @ApiResponse(responseCode = "200", description = "OTP đã được xác nhận thành công")
            })
    @PostMapping("/verify-otp")
    public ApiResponses<TokenResponse> verifyOtp(@RequestBody VerifyOtpRequest verifyOtpRequest) {
        TokenResponse result = ((SelfIDPAuthService) authService).verifyOtp(verifyOtpRequest);
        return ApiResponses.<TokenResponse>builder()
                .data(result)
                .success(true)
                .code(200)
                .message("OTP đã được xác nhận thành công")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
    }

    @Operation(summary = "Đăng xuất",
            description = "API này sẽ đăng xuất người dùng khỏi hệ thống.",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Đăng xuất thành công")
            })
    @PostMapping("/logout-user")
    ApiResponses<String> logoutIam(@Parameter(description = "request", hidden = true) HttpServletRequest request,
                                    @Parameter(description = "Refresh token từ client", required = true) @RequestParam String refreshToken
                                   ) {
        authService.logoutIam(request, refreshToken);
        return ApiResponses.<String>builder()
                .data("Logout successful")
                .success(true)
                .code(200)
                .message("Logout successful")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
    }

    @Operation(summary = "Refresh Token",
            description = "API này sẽ refresh token và trả về token mới.",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Refresh Token thành công")
            })
    @PostMapping("/refresh")
    ApiResponses<TokenResponse> refresh(@Parameter(description = "Refresh token từ client", required = true)
                                            @RequestParam("refreshToken") String refreshToken) {
        TokenResponse tokenResponse = authService.refresh(refreshToken);
        return ApiResponses.<TokenResponse>builder()
                .data(tokenResponse)
                .success(true)
                .code(200)
                .message("Refresh Token successful")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
    }

    @Operation(summary = "Yêu cầu reset mật khẩu với Self IDP / Reset mật khẩu với Keycloak",
            description = "API này sẽ gửi link reset mật khẩu đến email với Self IDP / Reset mật khẩu với Keycloak.",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Thông tin mật khẩu",
                    required = true,
                    content = @io.swagger.v3.oas.annotations.media.Content(
                            schema = @Schema(implementation = ResetPasswordRequest.class)
                    )
            ),
            responses = {
                    @ApiResponse(responseCode = "200", description = "Thành công")
            })
    @PostMapping("/forgot-password")
    public ApiResponses<Void> requestPasswordReset(@Parameter(description = "Tên tài khoản của nguười dùng", required = true)
                                                       @RequestParam String username,
                                                       @RequestBody(required = false) ResetPasswordRequest resetPasswordRequest) {
        authService.requestPasswordReset(username, resetPasswordRequest);
        return ApiResponses.<Void>builder()
                .success(true)
                .code(200)
                .message(keycloakEnabled?"Password successfully reset":"Reset password link sent to email")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
    }

    @Operation(summary = "Reset mật khẩu",
            description = "API này sẽ reset mật khẩu.",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Thông tin mật khẩu",
                    required = true,
                    content = @io.swagger.v3.oas.annotations.media.Content(
                            schema = @Schema(implementation = ResetPasswordRequest.class)
                    )
            ),
            responses = {
                    @ApiResponse(responseCode = "200", description = "Mật khẩu đã được reset")
            })
    @PatchMapping("/reset-password")
    public ApiResponses<Void> resetPassword(@RequestParam String token, @RequestBody ResetPasswordRequest resetPasswordRequest) {
        authService.resetPassword(token, resetPasswordRequest);
        return ApiResponses.<Void>builder()
                .success(true)
                .code(200)
                .message("Password successfully reset")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
    }
}
