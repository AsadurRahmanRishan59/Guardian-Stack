package com.rishan.guardianstack.masteradmin.user.controller;

import com.rishan.guardianstack.auth.model.SignUpMethod;
import com.rishan.guardianstack.core.response.ApiResponse;
import com.rishan.guardianstack.core.response.PaginatedResponse;
import com.rishan.guardianstack.masteradmin.user.dto.*;
import com.rishan.guardianstack.masteradmin.user.service.MasterAdminUserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;

@RestController
@RequestMapping("/masteradmin/users")
@Validated
@RequiredArgsConstructor
@PreAuthorize("hasRole('MASTER_ADMIN')") // Global security for this controller
public class MasterAdminUserController {

    private final MasterAdminUserService masterAdminUserService;


    @GetMapping
    public ResponseEntity<PaginatedResponse<MasterAdminUserViewDTO>> getAllUsers(
            @RequestParam(required = false) String username,
            @RequestParam(required = false) String email,
            @RequestParam(required = false) Boolean enabled,
            @RequestParam(required = false) Boolean accountLocked,
            @RequestParam(required = false) Boolean accountExpired,
            @RequestParam(required = false) Boolean credentialExpired,
            @RequestParam(required = false) SignUpMethod signUpMethod,
            @RequestParam(required = false) List<Integer> roleIds,

            @RequestParam(defaultValue = "0") Integer page,
            @RequestParam(defaultValue = "10") Integer size,
            @RequestParam(defaultValue = "username") String sortBy,
            @RequestParam(defaultValue = "asc") String sortDirection) {
        MasterAdminUserSearchCriteria searchCriteria = new MasterAdminUserSearchCriteria(
                username, email, enabled, accountLocked, accountExpired, credentialExpired, signUpMethod, roleIds, page, size, sortBy, sortDirection
        );
        PaginatedResponse<MasterAdminUserViewDTO> response = masterAdminUserService.getAllUsers(searchCriteria);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/{userId}")
    public ResponseEntity<ApiResponse<MasterAdminUserDTO>> getUser(@PathVariable Long userId) {
        MasterAdminUserDTO dto = masterAdminUserService.getUserById(userId);
        return ResponseEntity.ok(new ApiResponse<>(true, "User " + dto.username() + " fetched successfully", dto, LocalDateTime.now()));
    }

    /**
     * Create a new user (Staff or Admin)
     */
    @PostMapping
    public ResponseEntity<ApiResponse<Void>> createUser(@Valid @RequestBody CreateUserRequestDTO dto) {
        Long id = masterAdminUserService.createUser(dto);
        return ResponseEntity.status(HttpStatus.CREATED).body(
                new ApiResponse<>(
                        true,
                        "User with id: " + id + " created successfully",
                        null,
                        LocalDateTime.now()
                )
        );
    }

    /**
     * Update an existing user's details and roles
     */
    @PutMapping("/{userId}")
    public ResponseEntity<ApiResponse<Void>> updateUser(
            @PathVariable Long userId,
            @Valid @RequestBody UpdateUserRequestDTO dto) {

        masterAdminUserService.updateUser(dto, userId);
        return ResponseEntity.ok(
                new ApiResponse<>(
                        true,
                        "User with id: " + userId + " updated successfully",
                        null,
                        LocalDateTime.now()
                )
        );
    }

    //filter options
    @GetMapping("/filter-options")
    public ResponseEntity<ApiResponse<MasterAdminUserFilterOptions>> getFilterOptions() {
        MasterAdminUserFilterOptions options = masterAdminUserService.getFilterOptions();
        return ResponseEntity.ok(
                new ApiResponse<>(
                        true,
                        "Filter options retrieved successfully",
                        options,
                        LocalDateTime.now()));
    }
}