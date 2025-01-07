package com.evotek.iam.service.common;

import com.evotek.iam.dto.request.LoginRequest;
import com.evotek.iam.dto.request.identityKeycloak.ResetPasswordRequest;
import com.evotek.iam.dto.response.TokenResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;

@Service
public interface AuthService {
    boolean introspect(String token);
    TokenResponse authenticate(LoginRequest loginRequest);
    void logoutIam(HttpServletRequest request, String refreshToken);
    TokenResponse refresh(String refreshToken);
    void requestPasswordReset(String username, ResetPasswordRequest resetPasswordRequest);
    void resetPassword(String token, ResetPasswordRequest resetPasswordRequest);
}
