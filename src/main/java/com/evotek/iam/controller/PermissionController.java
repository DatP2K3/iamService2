package com.evotek.iam.controller;

import com.evotek.iam.dto.ApiResponses;
import com.evotek.iam.dto.request.PermissionRequest;
import com.evotek.iam.dto.response.PageResponse;
import com.evotek.iam.model.Permission;
import com.evotek.iam.service.common.PermissionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class PermissionController {
    private final PermissionService permissionService;

    @Operation(summary = "Tạo mới quyền",
            description = "API này sẽ tạo mới một quyền trong hệ thống và trả về thông tin.",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Thông tin của quyền cần tạo mới",
                    required = true,
                    content = @io.swagger.v3.oas.annotations.media.Content(
                            schema = @Schema(implementation = PermissionRequest.class)
                    )
            ),
            responses = {
                    @ApiResponse(responseCode = "201", description = "Quyền đã được tạo mới")
            })
    @PreAuthorize("hasPermission('permission', 'create')")
    @PostMapping("/permissions")
    public ApiResponses<Permission> createPermission(@RequestBody PermissionRequest permissionRequest) {
        Permission permission = permissionService.createPermission(permissionRequest);
        return ApiResponses.<Permission>builder()
                .data(permission)
                .success(true)
                .code(201)
                .message("Permission created successfully")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
    }

    @Operation(summary = "Lấy danh sách quyền",
            description = "API này sẽ trả về danh sách quyền trong hệ thống.",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Danh sách quyền đã được trả về")
            })
    @GetMapping("/permissions/search")
    @PreAuthorize("hasPermission('permission', 'read')")
    public ApiResponses<PageResponse<Permission>> search(@Parameter(description = "Từ khóa cần tìm kiếm", example = "John Doe")
                                                             @RequestParam String keyword,

                                                                 @Parameter(description = "Chỉ số trang bắt đầu từ 0", example = "0")
                                                             @RequestParam int pageIndex,

                                                                 @Parameter(description = "Kích thước mỗi trang", example = "10")
                                                             @RequestParam int pageSize,

                                                                 @Parameter(description = "Cột dùng để sắp xếp", example = "username")
                                                             @RequestParam String sortBy) {
        return ApiResponses.<PageResponse<Permission>>builder()
                .data(permissionService.search(keyword, pageIndex, pageSize, sortBy))
                .success(true)
                .code(200)
                .message("Get permissions successfully")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
    }
}
