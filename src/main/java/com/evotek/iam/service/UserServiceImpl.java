package com.evotek.iam.service;

import com.evotek.iam.dto.request.PasswordRequestDTO;
import com.evotek.iam.dto.request.UserInforRequestDTO;
import com.evotek.iam.dto.request.UserRequestDTO;
import com.evotek.iam.dto.response.UserResponseDTO;
import com.evotek.iam.exception.ResourceNotFoundException;
import com.evotek.iam.exception.UserAlreadyExistsException;
import com.evotek.iam.mapper.UserMapper;
import com.evotek.iam.model.Role;
import com.evotek.iam.model.User;
import com.evotek.iam.model.UserActivityLog;
import com.evotek.iam.repository.RoleRepository;
import com.evotek.iam.repository.UserActivityLogRepository;
import com.evotek.iam.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;
    private final CloudinaryService cloudinaryService;
    private final EmailService emailService;
    private final UserActivityLogRepository userActivityLogRepository;

    @Override
    public UserResponseDTO getUserById(int id) {
        User user = userRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("User with id " + id + " not found"));
        return userMapper.userToUserResponseDTO(user);
    }

    @Override
    public List<UserResponseDTO> getAllUsers() {
        return userRepository.findAll().stream().map(userMapper::userToUserResponseDTO).collect(Collectors.toList());
    }

    @Override
    public UserResponseDTO createUser(UserRequestDTO userRequestDTO) {
        if (userRepository.existsByEmail((userRequestDTO.getEmail()))) {
            throw new UserAlreadyExistsException(userRequestDTO.getEmail() + " already exists");
        }
        User user = userMapper.UserRequestDTOToUser(userRequestDTO);
        String password = passwordEncoder.encode(user.getPassword());
        user.setPassword(password);
        Role role = roleRepository.findById(userRequestDTO.getRoleId())
                .orElseThrow(() -> new ResourceNotFoundException("Role not found with id: " + userRequestDTO.getRoleId()));
        role.assignRoleToUser(user);
        emailService.sendMailAlert(user.getEmail(), "signin");
        return userMapper.userToUserResponseDTO(userRepository.save(user));
    }

    @Override
    public UserResponseDTO updateInfoUser(int id, UserInforRequestDTO userInforRequestDTO) {
        User user = userRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("User with id " + id + " not found"));
        if (userInforRequestDTO.getFullName() != null) {
            user.setFullName(userInforRequestDTO.getFullName());
        }
        if (userInforRequestDTO.getBirthDate() != null) {
            user.setBirthDate(LocalDate.parse(userInforRequestDTO.getBirthDate()));
        }
        if (userInforRequestDTO.getPhone() != null) {
            user.setPhone(userInforRequestDTO.getPhone());
        }
        if (userInforRequestDTO.getAddress() != null) {
            user.setAddress(userInforRequestDTO.getAddress());
        }
        emailService.sendMailAlert(user.getEmail(), "change_info");
        return userMapper.userToUserResponseDTO(userRepository.save(user));
    }

    @Override
    public void updatePassword(int id, PasswordRequestDTO passwordRequestDTO) {
        User user = userRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("User with id " + id + " not found"));
        if(passwordEncoder.matches(passwordRequestDTO.getOldPassword(), user.getPassword())){
            user.setPassword(passwordEncoder.encode(passwordRequestDTO.getNewPassword()));
            userRepository.save(user);
            emailService.sendMailAlert(user.getEmail(), "change_password");

            UserActivityLog log = new UserActivityLog();
            log.setUserId(user.getId());
            log.setActivity("Change PassWord");
            log.setCreatedAt(LocalDateTime.now());
            userActivityLogRepository.save(log);
        } else {
            throw new ResourceNotFoundException("Old password is incorrect");
        }
    }

    @Override
    public String updateAvatar(int id, MultipartFile file) {
        User user = userRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("User with id " + id + " not found"));
        Map data = this.cloudinaryService.upLoadFile(file);
        String avatar = (String) data.get("url");
        user.setAvatar(avatar);
        userRepository.save(user);
        emailService.sendMailAlert(user.getEmail(), "change_info");
        return avatar;
    }

    @Override
    public void deleteUser(int id) {
        User user = userRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("User with id " + id + " not found"));
        Role role = user.getRole();
        role.removeUserFromRole(user);
        userRepository.delete(user);
    }
}
