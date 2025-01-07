package com.evotek.iam.repository;

import com.evotek.iam.model.Permission;

import java.util.List;

public interface PermissionCustom {

    List<Permission> search(String keyword, int pageIndex, int pageSize, String sortBy);
}
