package com.evotek.iam.controller;

import com.evotek.iam.dto.request.PasswordRequestDTO;
import com.evotek.iam.dto.request.UserInforRequestDTO;
import com.evotek.iam.dto.request.UserRequestDTO;
import com.evotek.iam.dto.response.UserResponseDTO;
import com.evotek.iam.service.UserService;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PUBLIC)
public class UserController {
    private final UserService userService;

    @PostMapping("/users")
    ResponseEntity<UserResponseDTO> createUser(@RequestBody UserRequestDTO userRequestDTO) {
        UserResponseDTO userResponseDTO =  userService.createUser(userRequestDTO);
        return ResponseEntity.ok(userResponseDTO);
    }

    @GetMapping("/users/{id}")
    ResponseEntity<UserResponseDTO> getUserById(@PathVariable int id) {
        UserResponseDTO userResponseDTO =  userService.getUserById(id);
        return ResponseEntity.ok(userResponseDTO);
    }

    @GetMapping("/users")
    ResponseEntity<List<UserResponseDTO>> getAllUsers() {
        List<UserResponseDTO> userResponseDTOs =  userService.getAllUsers();
        return ResponseEntity.ok(userResponseDTOs);
    }

    @PatchMapping("/users/{id}/info")
    ResponseEntity<UserResponseDTO> updateInfoUser(@PathVariable int id, @RequestBody UserInforRequestDTO userInforRequestDTO) {
        UserResponseDTO userResponseDTO =  userService.updateInfoUser(id, userInforRequestDTO);
        return ResponseEntity.ok(userResponseDTO);
    }

    @PatchMapping("/users/{id}/password")
    ResponseEntity<Void> updatePassword(@PathVariable int id, @RequestBody PasswordRequestDTO passwordRequestDTO) {
        userService.updatePassword(id, passwordRequestDTO);
        return ResponseEntity.ok().build();
    }
}
