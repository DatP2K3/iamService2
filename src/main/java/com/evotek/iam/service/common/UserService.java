package com.evotek.iam.service.common;

import com.evotek.iam.dto.request.*;
import com.evotek.iam.dto.request.identityKeycloak.DeleteUserRequest;
import com.evotek.iam.dto.request.identityKeycloak.LockUserRequest;
import com.evotek.iam.dto.response.UserResponseDTO;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@Service
public interface UserService {
    UserResponseDTO getMyInfo(HttpServletRequest request);
    List<UserResponseDTO> getListUsers(GetUserRequest getUserRequest);
    UserResponseDTO createUser(UserRequestDTO userRequestDTO);
    UserResponseDTO updateInfoUser(int id, UserInforRequestDTO userInforRequestDTO);
    void updatePassword(int id, PasswordRequestDTO passwordRequestDTO);
    String updateAvatar(int id, MultipartFile avatar);
    void updateUser(String user_id,  UpdateUserRequest updateUserRequest);
}
