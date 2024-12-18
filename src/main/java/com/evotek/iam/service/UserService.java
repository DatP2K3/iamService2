package com.evotek.iam.service;

import com.evotek.iam.dto.request.PasswordRequestDTO;
import com.evotek.iam.dto.request.UserInforRequestDTO;
import com.evotek.iam.dto.request.UserRequestDTO;
import com.evotek.iam.dto.response.UserResponseDTO;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

public interface UserService {
    UserResponseDTO getUserById(int id);
    List<UserResponseDTO> getAllUsers();
    UserResponseDTO createUser(UserRequestDTO userRequestDTO);
    UserResponseDTO updateInfoUser(int id, UserInforRequestDTO userInforRequestDTO);
    void updatePassword(int id, PasswordRequestDTO passwordRequestDTO);
    String updateAvatar(int id, MultipartFile avatar);
    void deleteUser(int id);
}
