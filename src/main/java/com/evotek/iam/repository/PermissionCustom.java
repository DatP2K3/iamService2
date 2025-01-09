package com.evotek.iam.repository;

import com.evotek.iam.dto.request.PermissionSearchRequest;
import com.evotek.iam.model.Permission;

import java.util.List;

public interface PermissionCustom {

    List<Permission> search(PermissionSearchRequest permissionSearchRequest);
}
