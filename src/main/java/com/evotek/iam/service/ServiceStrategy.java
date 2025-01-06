package com.evotek.iam.service;

import com.evotek.iam.service.common.AuthService;
import com.evotek.iam.service.common.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
@RequiredArgsConstructor
public class ServiceStrategy {
    private final Map<String, AuthService> authService;
    public AuthService getAuthService(String type) {return authService.get(type);}
}
