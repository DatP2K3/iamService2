package com.evotek.iam.mapper;

import com.evotek.iam.dto.request.UserRequest;
import com.evotek.iam.dto.response.UserResponse;
import com.evotek.iam.model.User;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface UserMapper {
    UserResponse userToUserResponse(User user);
    @Mapping(target = "locked", constant = "false")
    User UserRequestToUser(UserRequest userRequest);
}
