package com.evotek.iam.service.common;

import com.evotek.iam.dto.request.PermissionRequest;
import com.evotek.iam.dto.response.PageResponse;
import com.evotek.iam.model.Permission;
import com.evotek.iam.model.RolePermission;
import com.evotek.iam.repository.PermissionsRepository;
import com.evotek.iam.repository.RolePermissionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class PermissionService {
    private final PermissionsRepository permissionsRepository;
    private final RolePermissionRepository rolePermissionRepository;
    public Permission createPermission(PermissionRequest permissionRequest) {
        Permission permission = permissionsRepository.findByResourceIdAndScope(permissionRequest.getResourceId(), permissionRequest.getScope());

        if(permission == null) {
            permission = Permission.builder()
                    .resourceId(permissionRequest.getResourceId())
                    .scope(permissionRequest.getScope())
                    .build();
            permissionsRepository.save(permission);
        }

        RolePermission rolePermission = RolePermission.builder()
                .roleId(permissionRequest.getRoleId())
                .permissionId(permission.getId())
                .build();
        rolePermissionRepository.save(rolePermission);
        return permission;
    }

    public PageResponse<Permission> search(String keyword, int pageIndex, int pageSize, String sortBy) {
        List<Permission> permissions = permissionsRepository.search(keyword, pageIndex, pageSize, sortBy);
        return PageResponse.<Permission>builder().userResponses(permissions).pageIndex(pageIndex).pageSize(pageSize).build();
    }
}
