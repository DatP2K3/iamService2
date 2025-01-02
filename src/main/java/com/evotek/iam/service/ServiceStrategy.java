package com.evotek.iam.service;

import com.evotek.iam.service.common.AuthService2;
import com.evotek.iam.service.common.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
@RequiredArgsConstructor
public class ServiceStrategy {
    private final Map<String, UserService> userServices;
    private final Map<String, AuthService2> authService;

    public UserService getUserService(String type) {
        return userServices.get(type);
    }
    public AuthService2 getAuthService(String type) {return authService.get(type);}
}
