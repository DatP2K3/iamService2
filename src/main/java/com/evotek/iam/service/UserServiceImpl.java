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
import com.evotek.iam.repository.RoleRepository;
import com.evotek.iam.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;

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
        return userMapper.userToUserResponseDTO(userRepository.save(user));
    }

    @Override
    public void updatePassword(int id, PasswordRequestDTO passwordRequestDTO) {
        User user = userRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("User with id " + id + " not found"));
        if(passwordEncoder.matches(passwordRequestDTO.getOldPassword(), user.getPassword())){
            user.setPassword(passwordEncoder.encode(passwordRequestDTO.getNewPassword()));
            userRepository.save(user);
        } else {
            throw new ResourceNotFoundException("Old password is incorrect");
        }
    }

    @Override
    public void updateAvatar(int id, String avatar) {
        User user = userRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("User with id " + id + " not found"));
        user.setAvatar(avatar);
        userRepository.save(user);
    }

    @Override
    public void deleteUser(int id) {
        User user = userRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("User with id " + id + " not found"));
        Role role = user.getRole();
        role.assignRoleToUser(null);
        userRepository.delete(user);
    }
}
