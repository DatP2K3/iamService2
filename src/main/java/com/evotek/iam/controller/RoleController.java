package com.evotek.iam.controller;

import com.evotek.iam.dto.ApiResponses;
import com.evotek.iam.dto.request.RoleRequest;
import com.evotek.iam.dto.request.UpdateUserRequest;
import com.evotek.iam.model.Role;
import com.evotek.iam.service.common.RoleService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class RoleController {
    private final RoleService roleService;

    @Operation(summary = "Tạo mới vai trò",
            description = "API này sẽ tạo mới một vai trò trong hệ thống và trả về thông tin.",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Thông tin của vai trò cần tạo mới",
                    required = true,
                    content = @io.swagger.v3.oas.annotations.media.Content(
                            schema = @Schema(implementation = RoleRequest.class)
                    )
            ),
            responses = {
                    @ApiResponse(responseCode = "201", description = "Vai trò đã được tạo mới")
            })
    @PreAuthorize("hasPermission('role', 'create')")
    @PostMapping("/roles")
    public ApiResponses<Role> createRole(@RequestBody RoleRequest roleRequest) {
         Role role =  roleService.createRole(roleRequest);
        return ApiResponses.<Role>builder()
                .data(role)
                .success(true)
                .code(201)
                .message("Role created successfully")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
    }

    @Operation(summary = "Lấy danh sách vai trò",
            description = "API này sẽ trả về danh sách vai trò trong hệ thống.",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Danh sách vai trò đã được trả về")
            })
    @PreAuthorize("hasPermission('role', 'read')")
    @GetMapping("/roles")
    public ApiResponses<List<Role>> getRoles() {
        List<Role> roles = roleService.getRoles();
        return ApiResponses.<List<Role>>builder()
                .data(roles)
                .success(true)
                .code(200)
                .message("Get roles successfully")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
    }
}
