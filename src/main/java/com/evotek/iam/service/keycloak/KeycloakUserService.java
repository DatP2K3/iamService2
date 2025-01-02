package com.evotek.iam.service.keycloak;

import com.evotek.iam.dto.request.*;
import com.evotek.iam.dto.request.identityKeycloak.*;
import com.evotek.iam.dto.response.UserResponseDTO;
import com.evotek.iam.exception.AppException;
import com.evotek.iam.exception.ErrorCode;
import com.evotek.iam.exception.ErrorNormalizer;
import com.evotek.iam.mapper.UserMapper;
import com.evotek.iam.model.User;
import com.evotek.iam.repository.IdentityClient;
import com.evotek.iam.repository.UserRepository;
import com.evotek.iam.service.common.UserService;
import feign.FeignException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Map;

@Component("keycloak_user_service")
@RequiredArgsConstructor
public class KeycloakUserService implements UserService {
    private final UserRepository userRepository;
    private final UserMapper userMapper;
    private final IdentityClient identityClient;
    private final ErrorNormalizer errorNormalizer;
    private final PasswordEncoder passwordEncoder;

    @Value("${idp.client-id}")
    private String clientId;
    @Value("${idp.client-secret}")
    private String clientSecret;

    @Override
    public UserResponseDTO getMyInfo(HttpServletRequest request) {
        try {
            String token = request.getHeader("Authorization");
            ResponseEntity<Map<String, String>> response = identityClient.getUserInfo(token);
            return UserResponseDTO.builder()
                    .username(response.getBody().get("preferred_username").toString())
                    .email(response.getBody().get("email").toString())
                    .firstName(response.getBody().get("given_name").toString())
                    .lastName(response.getBody().get("family_name").toString())
                    .build();
        } catch (FeignException e) {
            throw errorNormalizer.handleKeyCloakException(e);
        }
    }

    @Override
    public List<UserResponseDTO> getListUsers(GetUserRequest getUserRequest) {
        try {
            var token = identityClient.getToken(TokenRequest.builder()
                    .grant_type("client_credentials")
                    .client_id(clientId)
                    .client_secret(clientSecret)
                    .scope("openid")
                    .build());

            List<UserResponseDTO> listUserResponse = identityClient.getUser("Bearer " + token.getAccessToken(), getUserRequest.getUsername(), getUserRequest.getFirst(), getUserRequest.getMax());
            return listUserResponse;
        } catch (FeignException e) {
            throw errorNormalizer.handleKeyCloakException(e);
        }
    }

    @Override
    public UserResponseDTO createUser(UserRequestDTO userRequestDTO) {
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
                            .username(userRequestDTO.getUsername())
                            .firstName(userRequestDTO.getFirstName())
                            .lastName(userRequestDTO.getLastName())
                            .email(userRequestDTO.getEmail())
                            .enabled(true)
                            .emailVerified(false)

                            .credentials(List.of(CredentialRequestDTO.builder()
                                    .type("password")
                                    .temporary(false)
                                    .value(userRequestDTO.getPassword())
                                    .build()))
                            .build());

            String userId = extractUserId(creationResponse);
            User user = userMapper.UserRequestDTOToUser(userRequestDTO);
            user.setKeyCloakUserID(userId);
            String password = passwordEncoder.encode(user.getPassword());
            user.setPassword(password);
            user = userRepository.save(user);
            return userMapper.userToUserResponseDTO(user);
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
    public UserResponseDTO updateInfoUser(int id, UserInforRequestDTO userInforRequestDTO) {
        return null;
    }

    @Override
    public void updatePassword(int id, PasswordRequestDTO passwordRequestDTO) {

    }

    @Override
    public String updateAvatar(int id, MultipartFile avatar) {
        return "";
    }

    @Override
    public void updateUser(String username, UpdateUserRequest updateUserRequest) {
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
            userRepository.save(user);

        } catch (FeignException e) {
            throw errorNormalizer.handleKeyCloakException(e);
        }
    }
}