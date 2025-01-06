package com.evotek.iam.service.common;

import com.evotek.iam.dto.request.*;
import com.evotek.iam.dto.request.identityKeycloak.CredentialRequestDTO;
import com.evotek.iam.dto.request.identityKeycloak.LockUserRequest;
import com.evotek.iam.dto.request.identityKeycloak.TokenRequest;
import com.evotek.iam.dto.request.identityKeycloak.UserCreationParamRequestDTO;
import com.evotek.iam.dto.response.PageResponse;
import com.evotek.iam.dto.response.UserResponse;
import com.evotek.iam.exception.AppException;
import com.evotek.iam.exception.ErrorCode;
import com.evotek.iam.exception.ErrorNormalizer;
import com.evotek.iam.mapper.UserMapper;
import com.evotek.iam.model.Role;
import com.evotek.iam.model.User;
import com.evotek.iam.model.UserRole;
import com.evotek.iam.repository.IdentityClient;
import com.evotek.iam.repository.RoleRepository;
import com.evotek.iam.repository.UserRepository;
import com.evotek.iam.repository.UserRoleRepository;
import feign.FeignException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;

@Component("self_idp_user_service")
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;
    private final RoleRepository roleRepository;
    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;
    private final IdentityClient identityClient;
    private final ErrorNormalizer errorNormalizer;

    @Value("${idp.client-id}")
    private String clientId;
    @Value("${idp.client-secret}")
    private String clientSecret;

    @Override
    public UserResponse getUserInfo(String username) {
        User user = userRepository.findByUsername(username).orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
        return userMapper.userToUserResponse(user);
    }

    @Override
    public UserResponse createUser(UserRequest userRequest) {
        try {
            var token = identityClient.getToken(TokenRequest.builder()
                    .grant_type("client_credentials")
                    .client_id(clientId)
                    .client_secret(clientSecret)
                    .scope("openid")
                    .build());

            var creationResponse = identityClient.createUser(
                    "Bearer " + token.getAccessToken(),
                    UserCreationParamRequestDTO.builder()
                            .username(userRequest.getUsername())
                            .firstName(userRequest.getFirstName())
                            .lastName(userRequest.getLastName())
                            .email(userRequest.getEmail())
                            .enabled(true)
                            .emailVerified(false)

                            .credentials(List.of(CredentialRequestDTO.builder()
                                    .type("password")
                                    .temporary(false)
                                    .value(userRequest.getPassword())
                                    .build()))
                            .build());

            String userId = extractUserId(creationResponse);
            User user = userMapper.UserRequestToUser(userRequest);
            user.setKeyCloakUserID(userId);
            String password = passwordEncoder.encode(user.getPassword());
            user.setPassword(password);
            user = userRepository.save(user);
            Role role = roleRepository.findByName("ROLE_USER").orElseThrow(() -> new AppException(ErrorCode.ROLE_NOT_EXISTED));
            UserRole userRole = UserRole.builder()
                    .userId(user.getSelfUserID())
                    .roleId(role.getId())
                    .build();
            userRoleRepository.save(userRole);
            return userMapper.userToUserResponse(user);
        } catch (FeignException e) {
            throw errorNormalizer.handleKeyCloakException(e);
        }
    }

    @Override
    public UserResponse createAdminister(UserRequest userRequest) {
        try {
            var token = identityClient.getToken(TokenRequest.builder()
                    .grant_type("client_credentials")
                    .client_id(clientId)
                    .client_secret(clientSecret)
                    .scope("openid")
                    .build());

            var creationResponse = identityClient.createUser(
                    "Bearer " + token.getAccessToken(),
                    UserCreationParamRequestDTO.builder()
                            .username(userRequest.getUsername())
                            .firstName(userRequest.getFirstName())
                            .lastName(userRequest.getLastName())
                            .email(userRequest.getEmail())
                            .enabled(true)
                            .emailVerified(false)

                            .credentials(List.of(CredentialRequestDTO.builder()
                                    .type("password")
                                    .temporary(false)
                                    .value(userRequest.getPassword())
                                    .build()))
                            .build());

            String userId = extractUserId(creationResponse);
            User user = userMapper.UserRequestToUser(userRequest);
            user.setKeyCloakUserID(userId);
            String password = passwordEncoder.encode(user.getPassword());
            user.setPassword(password);

            Role role = roleRepository.findByName(userRequest.getRole()).orElseThrow(() -> new AppException(ErrorCode.ROLE_NOT_EXISTED));
            user = userRepository.save(user);

            UserRole userRole = UserRole.builder()
                    .userId(user.getSelfUserID())
                    .roleId(role.getId())
                    .build();
            userRoleRepository.save(userRole);

            return userMapper.userToUserResponse(user);
        } catch (FeignException e) {
            throw errorNormalizer.handleKeyCloakException(e);
        }
    }

    private String extractUserId(ResponseEntity<?> response) {
        String location = response.getHeaders().get("Location").getFirst();
        String[] splitedStr = location.split("/");
        return splitedStr[splitedStr.length - 1];
    }

    @Override
    public void updatePassword(int id, PasswordRequest passwordRequest) {

    }

    @Override
    public UserResponse updateUser(String username, UpdateUserRequest updateUserRequest) {
        try {
            User user = userRepository.findByUsername(username).orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
            String user_id = user.getKeyCloakUserID();

            var token = identityClient.getToken(TokenRequest.builder()
                    .grant_type("client_credentials")
                    .client_id(clientId)
                    .client_secret(clientSecret)
                    .scope("openid")
                    .build());

            identityClient.updateUser(
                    "Bearer " + token.getAccessToken(), user_id, updateUserRequest);

            if (updateUserRequest.getEmail() != null) {
                user.setEmail(updateUserRequest.getEmail());
            }
            if (updateUserRequest.getFirstName() != null) {
                user.setFirstName(updateUserRequest.getFirstName());
            }
            if (updateUserRequest.getLastName() != null) {
                user.setLastName(updateUserRequest.getLastName());
            }
            return userMapper.userToUserResponse(userRepository.save(user));

        } catch (FeignException e) {
            throw errorNormalizer.handleKeyCloakException(e);
        }
    }

    @Override
    public void deleteUser(String user_id, boolean deleted) {
        User user = userRepository.findBySelfUserID(Integer.parseInt(user_id)).orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
        user.setDeleted(deleted);
        userRepository.save(user);
    }

    @Override
    public void lockUser(String user_id, boolean enabled) {
        User user = userRepository.findBySelfUserID(Integer.parseInt(user_id)).orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
        user.setLocked(!enabled);
        userRepository.save(user);

        var token = identityClient.getToken(TokenRequest.builder()
                .grant_type("client_credentials")
                .client_id(clientId)
                .client_secret(clientSecret)
                .scope("openid")
                .build());

        identityClient.lockUser("Bearer " + token.getAccessToken(), user.getKeyCloakUserID(), LockUserRequest.builder().enabled(enabled).build());
    }

    @Override
    public PageResponse search(String keyword, int pageIndex, int pageSize, String sortBy) {
        List<User> users = userRepository.search(keyword, pageIndex, pageSize, sortBy);
        List<UserResponse> userResponseS = users.stream().map(userMapper::userToUserResponse).toList();
        return PageResponse.builder().userResponses(userResponseS).pageIndex(pageIndex).pageSize(pageSize).build();
    }

}