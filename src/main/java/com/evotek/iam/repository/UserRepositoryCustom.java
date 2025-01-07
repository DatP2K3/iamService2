package com.evotek.iam.repository;

import com.evotek.iam.model.User;

import java.util.List;

public interface UserRepositoryCustom {

    List<User> search(String keyword, int pageIndex, int pageSize, String sortBy);
}
