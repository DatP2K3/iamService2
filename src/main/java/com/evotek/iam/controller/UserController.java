package com.evotek.iam.controller;

import com.evotek.iam.dto.ApiResponses;
import com.evotek.iam.dto.request.UpdateUserRequest;
import com.evotek.iam.dto.request.UserRequest;
import com.evotek.iam.dto.response.PageResponse;
import com.evotek.iam.dto.response.UserResponse;
import com.evotek.iam.service.common.UserServiceImpl;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserController {
    private final UserServiceImpl userService;


    @Operation(summary = "Tạo mới người dùng",
            description = "API này sẽ tạo mới một người dùng trong hệ thống và trả về thông tin.",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Thông tin của người dùng cần tạo mới",
                    required = true,
                    content = @io.swagger.v3.oas.annotations.media.Content(
                            schema = @Schema(implementation = UserRequest.class)
                    )
            ),
            responses = {
                    @ApiResponse(responseCode = "201", description = "Người dùng đã được tạo mới")
            })
    @PostMapping("/users")
    public ApiResponses<UserResponse> createUser(@RequestBody @Valid UserRequest userRequest) {
        UserResponse userResponse = userService.createUser(userRequest);
        return ApiResponses.<UserResponse>builder()
                .data(userResponse)
                .success(true)
                .code(201)
                .message("User created successfully")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
    }

    @Operation(summary = "Tạo mới người quản trị",
            description = "API này sẽ tạo mới một người quản trị trong hệ thống và trả về thông tin.",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Thông tin của người quản trị cần tạo mới",
                    required = true,
                    content = @io.swagger.v3.oas.annotations.media.Content(
                            schema = @Schema(implementation = UserRequest.class)
                    )
            ),
            responses = {
                    @ApiResponse(responseCode = "201", description = "Người quản trị đã được tạo mới")
            })
    @PreAuthorize("hasPermission('user', 'admin')")
    @PostMapping("/administers")
    public ApiResponses<UserResponse> createAdminister(@RequestBody @Valid UserRequest userRequest) {
        UserResponse userResponse = userService.createAdminister(userRequest);
        return ApiResponses.<UserResponse>builder()
                .data(userResponse)
                .success(true)
                .code(201)
                .message("User created successfully")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
    }

    @Operation(summary = "Lấy thông tin người dùng",
            description = "API này sẽ trả về thông tin người dùng trong hệ thống.",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Thông tin người dùng")
            })
    @PreAuthorize("hasPermission('user', 'read')")
    @GetMapping("/users/my-info")
    public ApiResponses<UserResponse> getMyInfo(@Parameter(description = "Tên người dùng", required = true)
                                                    @RequestParam String username) {
        UserResponse userResponse = userService.getUserInfo(username);
        return ApiResponses.<UserResponse>builder()
                .data(userResponse)
                .success(true)
                .code(200)
                .message("Get my info successfully")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
    }

    @Operation(summary = "Cập nhật thông tin người dùng",
            description = "API này sẽ trả cập nhật thông tin người dùng trong hệ thống và trả về thông tin.",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Thông tin của người dùng cần cập nhật",
                    required = true,
                    content = @io.swagger.v3.oas.annotations.media.Content(
                            schema = @Schema(implementation = UpdateUserRequest.class)
                    )
            ),
            responses = {
                    @ApiResponse(responseCode = "200", description = "Thông tin người dùng sau khi cập nhật")
            })
    @PreAuthorize("hasPermission('user', 'update')")
    @PutMapping("/users")
    public ApiResponses<UserResponse> updateUser(@Parameter(description = "username of user account", required = true)
                                                     @RequestParam String username, @RequestBody UpdateUserRequest updateUserRequest) {
        UserResponse userResponse = userService.updateUser(username, updateUserRequest);
        return ApiResponses.<UserResponse>builder()
                .data(userResponse)
                .success(true)
                .code(200)
                .message("Update user successfully")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
    }

    @Operation(summary = "Tìm kiếm người dùng",
            description = "API này sẽ trả về danh sách người dùng theo từ khóa tìm kiếm.",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Danh sách người dùng")
            })
    @PreAuthorize("hasPermission('user', 'manage')")
    @GetMapping("/users/search")
    public ApiResponses<PageResponse> search(@Parameter(description = "Từ khóa cần tìm kiếm", example = "John Doe")
                                                 @RequestParam String keyword,

                                             @Parameter(description = "Chỉ số trang bắt đầu từ 0", example = "0")
                                                 @RequestParam int pageIndex,

                                             @Parameter(description = "Kích thước mỗi trang", example = "10")
                                                 @RequestParam int pageSize,

                                             @Parameter(description = "Cột dùng để sắp xếp", example = "username")
                                                 @RequestParam String sortBy) {
        PageResponse pageResponse = userService.search(keyword, pageIndex, pageSize, sortBy);
        return ApiResponses.<PageResponse>builder()
                .data(pageResponse)
                .success(true)
                .code(200)
                .message("Get list user successfully")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
    }

    @Operation(summary = "Xóa người dùng",
            description = "API này sẽ xóa một người dùng trong hệ thống.",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Xóa người dùng thành công")
            })
    @PreAuthorize("hasPermission('user', 'delete')")
    @DeleteMapping("/users/{selfUserID}")
    public ApiResponses<Void> deleteUser(@Parameter(description = "ID của người dùng cần xóa", example = "12345")
                                             @PathVariable String selfUserID,
                                         @Parameter(description = "Xác định xoá hay khôi phục người dùng", example = "true")
                                             @RequestParam boolean deleted) {
        userService.deleteUser(selfUserID, deleted);
        return ApiResponses.<Void>builder()
                .success(true)
                .code(200)
                .message("Delete user successfully")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
    }


    @Operation(summary = "Khóa/Mở khóa người dùng",
            description = "API này sẽ khoá hoặc mở khóa một người dùng trong hệ thống.",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Khóa/Mở khóa người dùng thành công")
            })
    @PreAuthorize("hasPermission('user', 'delete')")
    @PatchMapping("/users/{selfUserID}")
    public ApiResponses<Void> lockUser(@Parameter(description = "ID của người dùng cần cập nhật trạng thái", example = "12345")
                                           @PathVariable String selfUserID,
                                       @Parameter(description = "Trạng thái của người dùng: `true` để khoá, `false` để mở khoá", example = "true")
                                           @RequestParam boolean enabled) {
        userService.lockUser(selfUserID, enabled);
        return ApiResponses.<Void>builder()
                .success(true)
                .code(200)
                .message("Lock/Unlock user successfully")
                .timestamp(System.currentTimeMillis())
                .status("OK")
                .build();
    }
}
