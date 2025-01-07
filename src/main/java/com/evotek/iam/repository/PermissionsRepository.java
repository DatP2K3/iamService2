package com.evotek.iam.repository;

import com.evotek.iam.model.Permission;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PermissionsRepository extends JpaRepository<Permission, Integer>, PermissionCustom {
    Permission findByResourceIdAndScope(String resourceId, String scope);
}
