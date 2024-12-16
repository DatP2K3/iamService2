package com.evotek.iam.mapper;

import com.evotek.iam.dto.request.UserRequestDTO;
import com.evotek.iam.dto.response.UserResponseDTO;
import com.evotek.iam.model.User;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface UserMapper {
    @Mapping(source = "role.id", target = "roleId")
    UserResponseDTO userToUserResponseDTO(User user);
    User UserRequestDTOToUser(UserRequestDTO userRequestDTO);
}
