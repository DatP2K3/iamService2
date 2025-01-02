package com.evotek.iam.service.self_idp;

import com.evotek.iam.dto.request.*;
import com.evotek.iam.dto.response.UserResponseDTO;
import com.evotek.iam.exception.AppException;
import com.evotek.iam.exception.ErrorCode;
import com.evotek.iam.mapper.UserMapper;
import com.evotek.iam.model.User;
import com.evotek.iam.repository.UserRepository;
import com.evotek.iam.service.common.UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@Component("self_idp_user_service")
@RequiredArgsConstructor
public class SelfIDPUserService implements UserService {
    private final UserRepository userRepository;
    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserResponseDTO getMyInfo(HttpServletRequest request) {
        User user = userRepository.findByUsername(request.getUserPrincipal().getName()).orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
        return userMapper.userToUserResponseDTO(user);
    }

    @Override
    public List<UserResponseDTO> getListUsers(GetUserRequest getUserRequest) {
        Pageable pageable = PageRequest.of(getUserRequest.getPage(), getUserRequest.getMax());
        List<User> users = userRepository.findByUsernameContainingIgnoreCase(getUserRequest.getUsername(), pageable).getContent();
        return users.stream().map(userMapper::userToUserResponseDTO).toList();
    }

    @Override
    public UserResponseDTO createUser(UserRequestDTO userRequestDTO) {
        User user = userMapper.UserRequestDTOToUser(userRequestDTO);
        String password = passwordEncoder.encode(user.getPassword());
        user.setPassword(password);
        user = userRepository.save(user);
        return userMapper.userToUserResponseDTO(user);
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
    public void updateUser(String user_id, UpdateUserRequest updateUserRequest) {

    }

//    @Override
//    public void deleteUser(String user_id, boolean deleted) {
//        User user = userRepository.findBySelfUserID(Integer.parseInt(user_id)).orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
//        user.setDeleted(deleted);
//        userRepository.save(user);
//    }
//
//    @Override
//    public void lockUser(String user_id, LockUserRequest lockUserRequest) {
//        User user = userRepository.findBySelfUserID(Integer.parseInt(user_id)).orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
//        user.setLocked(lockUserRequest.isEnabled());
//        userRepository.save(user);
//    }
}
