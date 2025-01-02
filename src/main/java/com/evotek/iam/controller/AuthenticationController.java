//package com.evotek.iam.controller;
//
//import com.evotek.iam.dto.ApiResponse;
//import com.evotek.iam.dto.request.*;
//import com.evotek.iam.dto.response.AuthenticationResponseDTO;
//import com.evotek.iam.dto.response.IntrospectResponseDTO;
//import com.evotek.iam.service.AuthService;
//import com.nimbusds.jose.JOSEException;
//import jakarta.servlet.http.HttpServletRequest;
//import lombok.RequiredArgsConstructor;
//import org.springframework.http.ResponseEntity;
//import org.springframework.web.bind.annotation.*;
//
//import java.text.ParseException;
//
//@RestController
//@RequestMapping("/auth")
//@RequiredArgsConstructor
//public class AuthenticationController {
//    private final AuthService authService;
//
//    @PostMapping("/token")
//    public ResponseEntity<ApiResponse<String>> authenticate(@RequestBody AuthenticationRequestDTO request) {
//        authService.authenticate(request);
//
//        ApiResponse<String> response = ApiResponse.<String>builder()
//                .success(true)
//                .code(200)
//                .message("OTP đã được gửi tới email")
//                .timestamp(System.currentTimeMillis())
//                .status("OK")
//                .build();
//
//        return ResponseEntity.ok(response);
//    }
//
//    @PostMapping("/verify-otp")
//    public ResponseEntity<ApiResponse<AuthenticationResponseDTO>> verifyOtp(@RequestBody VerifyOtpRequestDTO verifyOtpRequestDTO) {
//        AuthenticationResponseDTO result = authService.verifyOtp(verifyOtpRequestDTO);
//        ApiResponse<AuthenticationResponseDTO> response = ApiResponse.<AuthenticationResponseDTO>builder()
//                .data(result)
//                .success(true)
//                .code(200)
//                .message("OTP đã được xác nhận thành công")
//                .timestamp(System.currentTimeMillis())
//                .status("OK")
//                .build();
//
//        return ResponseEntity.ok(response);
//    }
//
//    @PostMapping("/introspect")
//    public ResponseEntity<ApiResponse<IntrospectResponseDTO>> authenticate(@RequestBody IntrospectRequestDTO request)
//            throws ParseException, JOSEException {
//        IntrospectResponseDTO result = authService.introspect(request);
//        ApiResponse<IntrospectResponseDTO> apiResponse = ApiResponse.<IntrospectResponseDTO>builder()
//                .data(result)
//                .success(true)
//                .code(200)
//                .message("Xác thực thành công")
//                .timestamp(System.currentTimeMillis())
//                .status("OK")
//                .build();
//
//        return ResponseEntity.ok(apiResponse);
//    }
//
//    @PostMapping("/refresh")
//    public ResponseEntity<ApiResponse<AuthenticationResponseDTO>> refresh(HttpServletRequest request)
//            throws ParseException, JOSEException {
//        AuthenticationResponseDTO result = authService.refreshToken(request);
//
//        ApiResponse<AuthenticationResponseDTO> apiResponse = ApiResponse.<AuthenticationResponseDTO>builder()
//                .data(result)
//                .success(true)
//                .code(200)
//                .message("Refresh Token thành công")
//                .timestamp(System.currentTimeMillis())
//                .status("OK")
//                .build();
//
//        return ResponseEntity.ok(apiResponse);
//    }
//
//    @PostMapping("/logout")
//    public ResponseEntity<ApiResponse<Void>> logout(HttpServletRequest request, @RequestBody IntrospectRequestDTO refreshToken)
//            throws ParseException, JOSEException {
//        authService.logout(request, refreshToken);
//
//        ApiResponse<Void> apiResponse = ApiResponse.<Void>builder()
//                .success(true)
//                .code(200)
//                .message("Logout successful")
//                .timestamp(System.currentTimeMillis())
//                .status("OK")
//                .build();
//
//        return ResponseEntity.ok(apiResponse);
//    }
//
//    @PostMapping("/forgot-password")
//    public ResponseEntity<ApiResponse<String>> requestPasswordReset(@RequestParam String email) {
//        authService.requestPasswordReset(email);
//
//        ApiResponse<String> apiResponse = ApiResponse.<String>builder()
//                .success(true)
//                .code(200)
//                .message("Reset password link sent to email")
//                .timestamp(System.currentTimeMillis())
//                .status("OK")
//                .build();
//
//        return ResponseEntity.ok(apiResponse);
//    }
//
//    @PatchMapping("/reset-password")
//    public ResponseEntity<ApiResponse<String>> resetPassword(@RequestParam String token, @RequestBody PasswordRequestDTO passwordRequestDTO) {
//        authService.resetPassword(token, passwordRequestDTO.getNewPassword());
//        ApiResponse<String> apiResponse = ApiResponse.<String>builder()
//                .success(true)
//                .code(200)
//                .message("Password successfully reset")
//                .timestamp(System.currentTimeMillis())
//                .status("OK")
//                .build();
//
//        return ResponseEntity.ok(apiResponse);
//    }
//}