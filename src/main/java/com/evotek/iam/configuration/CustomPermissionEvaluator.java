package com.evotek.iam.configuration;

import com.evotek.iam.model.Permission;
import com.evotek.iam.model.RolePermission;
import com.evotek.iam.model.User;
import com.evotek.iam.model.UserRole;
import com.evotek.iam.repository.PermissionsRepository;
import com.evotek.iam.repository.RolePermissionRepository;
import com.evotek.iam.repository.UserRepository;
import com.evotek.iam.repository.UserRoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.List;

@Component
@RequiredArgsConstructor
public class CustomPermissionEvaluator implements PermissionEvaluator {
    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;
    private final RolePermissionRepository rolePermissionRepository;
    private  final PermissionsRepository permissionsRepository;
    @Value("${auth.keycloak-enabled}")
    private boolean keycloakEnabled;

    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        if (authentication == null || targetDomainObject == null || permission == null) {
            return false;
        }
        String username = "";
        if(keycloakEnabled){
            Jwt jwt = (Jwt) authentication.getPrincipal();
            username = jwt.getClaim("preferred_username");
        } else {
            username = authentication.getName();
        }

        String resurceId = (String) targetDomainObject;
        String scope = (String) permission;

        return checkPermissionForUser(username, resurceId, scope);
    }

    private boolean checkPermissionForUser(String username, String resurceId, String scope) {
        User user = userRepository.findByUsername(username).orElseThrow(() -> new RuntimeException("User not found"));
        if (user == null) {
            return false;
        }
        if(user.isRoot()) {
            return true;
        }

        UserRole userRole = userRoleRepository.findByUserId(user.getSelfUserID()).orElseThrow(() -> new RuntimeException("User role not found"));

        List<RolePermission> rolePermissions = rolePermissionRepository.findByRoleId(userRole.getRoleId());
        for (RolePermission rolePermission : rolePermissions) {
            Permission permission = permissionsRepository.findById(rolePermission.getPermissionId()).orElse(null);
            if (permission != null && permission.getResourceId().equals(resurceId) && permission.getScope().equals(scope)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        return false;
    }
}
