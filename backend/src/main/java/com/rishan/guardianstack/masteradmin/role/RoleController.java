package com.rishan.guardianstack.masteradmin.role;

import com.rishan.guardianstack.auth.model.Role;
import com.rishan.guardianstack.core.response.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/masteradmin/roles")
public class RoleController {

    private final RoleService roleService;

    @GetMapping
    public ResponseEntity<ApiResponse<List<Role>>> getAllRoles() {

        return ResponseEntity
                .status(HttpStatus.OK)
                .body(new ApiResponse<>(
                        true, "Roles retrieved successfully", roleService.getRoles(), LocalDateTime.now()
                ));
    }
}
