package com.evotek.iam.repository;

import com.evotek.iam.dto.request.UpdateUserRequest;
import com.evotek.iam.dto.request.identityKeycloak.*;
import com.evotek.iam.dto.response.TokenResponse;
import com.evotek.iam.dto.response.UserResponse;
import feign.QueryMap;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@FeignClient(name = "identity-client", url = "${idp.url}")
public interface IdentityClient {
    @PostMapping(value = "/realms/IamService/protocol/openid-connect/token",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    TokenResponse getToken(@QueryMap TokenRequest param);

    @PostMapping(value = "/admin/realms/IamService/users",
            consumes = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<?> createUser(
            @RequestHeader("authorization") String token,
            @RequestBody UserCreationParamRequestDTO param);

    @PostMapping(value = "/realms/IamService/protocol/openid-connect/logout",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    TokenResponse logout(
            @RequestHeader("authorization") String token,
            @QueryMap LogoutRequest logoutReqest);

    @PostMapping(value = "/realms/IamService/protocol/openid-connect/token",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    TokenResponse refreshToken(@QueryMap RefreshTokenRequest refreshTokenRequest);

    @PutMapping(value = "/admin/realms/IamService/users/{user_id}",
            consumes = MediaType.APPLICATION_JSON_VALUE)
    void updateUser(@RequestHeader("authorization") String token,
                  @PathVariable("user_id") String userId,
                  @RequestBody UpdateUserRequest updateUserRequest);

    @PutMapping(value = "/admin/realms/IamService/users/{user_id}",
            consumes = MediaType.APPLICATION_JSON_VALUE)
    void lockUser(@RequestHeader("authorization") String token,
                    @PathVariable("user_id") String userId,
                    @RequestBody LockUserRequest lockUserRequest);

    @GetMapping(value = "/admin/realms/IamService/users")
    List<UserResponse> getUser(
            @RequestHeader("authorization") String token,
            @RequestParam String username,
            @RequestParam int first,
            @RequestParam int max);

    @PutMapping(value = "/admin/realms/IamService/users/{user_id}/reset-password",
            consumes = MediaType.APPLICATION_JSON_VALUE)
    void resetPassword(@RequestHeader("authorization") String token,
                    @PathVariable("user_id") String userId,
                    @RequestBody ResetPasswordRequest resetPasswordRequest);

    @GetMapping(value = "/realms/IamService/protocol/openid-connect/userinfo")
    ResponseEntity<Map<String, String>> getUserInfo(@RequestHeader("authorization") String token);
}
