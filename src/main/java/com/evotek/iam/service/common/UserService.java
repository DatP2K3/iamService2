package com.evotek.iam.service.common;

import com.evotek.iam.dto.request.*;
import com.evotek.iam.dto.response.PageResponse;
import com.evotek.iam.dto.response.UserResponse;
import jakarta.validation.Valid;
import org.springframework.stereotype.Service;

@Service
public interface UserService {
    UserResponse getUserInfo(String username);
    UserResponse createUser(UserRequest userRequest);
    void updatePassword(int id, PasswordRequest passwordRequest);
    UserResponse updateUser(String username,  UpdateUserRequest updateUserRequest);

    void deleteUser(String user_id, boolean deleted);

    void lockUser(String user_id, boolean locked);

    PageResponse search(String keyword, int pageIndex, int pageSize, String sortBy);

    UserResponse createAdminister(@Valid UserRequest userRequest);
}
