package com.evotek.iam.controller;

import com.evotek.iam.dto.ApiResponse;
import com.evotek.iam.dto.request.GetUserRequest;
import com.evotek.iam.dto.request.UpdateUserRequest;
import com.evotek.iam.dto.request.UserRequestDTO;
import com.evotek.iam.dto.request.identityKeycloak.LockUserRequest;
import com.evotek.iam.dto.response.UserResponseDTO;
import com.evotek.iam.service.ServiceStrategy;
import com.evotek.iam.service.common.UserService;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserController2 {
    private String typeUserService ="keycloak_user_service";
    @Value("${auth.keycloak-enabled}")
    private boolean keycloakEnabled;
    private final ServiceStrategy serviceStrategy;
    private UserService userService;

    @PostConstruct
    public void init() {
        if (!keycloakEnabled) {
            this.typeUserService = "self_idp_user_service";
        }
        this.userService = serviceStrategy.getUserService(typeUserService);
    }

    @PostMapping("/users")
    public ApiResponse<UserResponseDTO> createUser(@RequestBody @Valid UserRequestDTO userRequestDTO) {
        UserResponseDTO userResponseDTO = userService.createUser(userRequestDTO);
        return ApiResponse.<UserResponseDTO>builder()
                .data(userResponseDTO)
                .success(true)
                .code(201)
                .message("User created successfully")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
    }

    @GetMapping("/users/my-info")
    public ApiResponse<UserResponseDTO> getMyInfo(HttpServletRequest request) {
        UserResponseDTO userResponseDTO = userService.getMyInfo(request);
        return ApiResponse.<UserResponseDTO>builder()
                .data(userResponseDTO)
                .success(true)
                .code(200)
                .message("Get my info successfully")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
    }

    @PutMapping("/users")
    public ApiResponse<Void> updateUser(@RequestParam String username, @RequestBody UpdateUserRequest updateUserRequest) {
        userService.updateUser(username, updateUserRequest);
        return ApiResponse.<Void>builder()
                .success(true)
                .code(200)
                .message("Update user successfully")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
    }

    @GetMapping("/users")
    public ApiResponse<List<UserResponseDTO>> getListUsers(@RequestBody GetUserRequest getUserRequest) {
        List<UserResponseDTO> getListUser = userService.getListUsers(getUserRequest);
        return ApiResponse.<List<UserResponseDTO>>builder()
                .data(getListUser)
                .success(true)
                .code(200)
                .message("Get list user successfully")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
    }
}
