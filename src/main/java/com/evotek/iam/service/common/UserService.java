package com.evotek.iam.service.common;

import com.evotek.iam.dto.request.*;
import com.evotek.iam.dto.request.identityKeycloak.ResetPasswordRequest;
import com.evotek.iam.dto.response.PageApiResponse;
import com.evotek.iam.dto.response.PageResponse;
import com.evotek.iam.dto.response.TokenResponse;
import com.evotek.iam.dto.response.UserResponse;
import jakarta.validation.Valid;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface UserService {
    UserResponse getUserInfo(String username);

    UserResponse createUser(UserRequest userRequest);

    UserResponse updateUser(String username,  UpdateUserRequest updateUserRequest);

    void deleteUser(String user_id, boolean deleted);

    void lockUser(String user_id, boolean locked);

    List<UserResponse> search(UserSearchRequest userSearchRequest);

    UserResponse createAdminister(@Valid UserRequest userRequest);

    void changePassword(String username, PasswordRequest passwordRequest);

    TokenResponse processOAuthPostLogin(Authentication authentication);
}
