package com.evotek.iam.repository;

import com.evotek.iam.dto.request.UserSearchRequest;
import com.evotek.iam.model.User;

import java.util.List;

public interface UserRepositoryCustom {

    List<User> search(UserSearchRequest userSearchRequest);
}
