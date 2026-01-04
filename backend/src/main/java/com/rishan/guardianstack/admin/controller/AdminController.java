package com.rishan.guardianstack.admin.controller;

import com.rishan.guardianstack.admin.dto.*;
import com.rishan.guardianstack.admin.service.AdminService;
import com.rishan.guardianstack.auth.model.User;
import com.rishan.guardianstack.core.response.ApiResponse;
import com.rishan.guardianstack.core.ratelimit.RateLimited;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/admin/employees")
@RequiredArgsConstructor
@PreAuthorize("hasAnyRole('ADMIN', 'MASTER_ADMIN')")
public class AdminController {

    private final AdminService adminService;

    /**
     * Create new employee account
     */
    @PostMapping
    @RateLimited(maxAttempts = 10, timeWindow = 1, unit = TimeUnit.HOURS)
    public ResponseEntity<ApiResponse<EmployeeResponse>> createEmployee(
            @Valid @RequestBody CreateEmployeeRequest request,
            HttpServletRequest httpRequest) {

        User employee = adminService.createEmployeeAccount(request, httpRequest);
        EmployeeResponse response = EmployeeResponse.from(employee);

        return ResponseEntity.ok(new ApiResponse<>(
                true,
                String.format("Employee %s created successfully. Temporary password sent to email.",
                        employee.getUsername()),
                response,
                LocalDateTime.now()
        ));
    }

    /**
     * Extend employee contract
     */
    @PostMapping("/extend-contract")
    @RateLimited(maxAttempts = 20, timeWindow = 1, unit = TimeUnit.HOURS)
    public ResponseEntity<ApiResponse<Void>> extendContract(
            @Valid @RequestBody ExtendAccountRequest request,
            HttpServletRequest httpRequest) {

        adminService.extendContract(request, httpRequest);

        return ResponseEntity.ok(new ApiResponse<>(
                true,
                String.format("Contract extended by %d days", request.additionalDays()),
                null,
                LocalDateTime.now()
        ));
    }

    /**
     * Force password change
     */
    @PostMapping("/{email}/force-password-change")
    @RateLimited(maxAttempts = 10, timeWindow = 1, unit = TimeUnit.HOURS)
    public ResponseEntity<ApiResponse<Void>> forcePasswordChange(
            @PathVariable String email,
            HttpServletRequest httpRequest) {

        adminService.forcePasswordChange(email, httpRequest);

        return ResponseEntity.ok(new ApiResponse<>(
                true,
                "Password change forced. User will be prompted on next login.",
                null,
                LocalDateTime.now()
        ));
    }

    /**
     * Reset employee password (admin generates new temporary password)
     */
    @PostMapping("/{email}/reset-password")
    @RateLimited(maxAttempts = 10, timeWindow = 1, unit = TimeUnit.HOURS)
    public ResponseEntity<ApiResponse<Void>> resetPassword(
            @PathVariable String email,
            HttpServletRequest httpRequest) {

        adminService.resetEmployeePassword(email, httpRequest);

        return ResponseEntity.ok(new ApiResponse<>(
                true,
                "Password reset successfully. New temporary password sent to email.",
                null,
                LocalDateTime.now()
        ));
    }

    /**
     * Deactivate employee
     */
    @PostMapping("/deactivate")
    @RateLimited(maxAttempts = 20, timeWindow = 1, unit = TimeUnit.HOURS)
    public ResponseEntity<ApiResponse<Void>> deactivateEmployee(
            @Valid @RequestBody DeactivateEmployeeRequest request,
            HttpServletRequest httpRequest) {

        adminService.deactivateEmployee(request.email(), request.reason(), httpRequest);

        return ResponseEntity.ok(new ApiResponse<>(
                true,
                "Employee deactivated successfully",
                null,
                LocalDateTime.now()
        ));
    }

    /**
     * Reactivate employee
     */
    @PostMapping("/reactivate")
    @RateLimited(maxAttempts = 20, timeWindow = 1, unit = TimeUnit.HOURS)
    public ResponseEntity<ApiResponse<Void>> reactivateEmployee(
            @Valid @RequestBody ReactivateEmployeeRequest request,
            HttpServletRequest httpRequest) {

        adminService.reactivateEmployee(request.email(), request.contractDays(), httpRequest);

        return ResponseEntity.ok(new ApiResponse<>(
                true,
                "Employee reactivated successfully",
                null,
                LocalDateTime.now()
        ));
    }

    /**
     * Get expiring employees (within N days)
     */
    @GetMapping("/expiring")
    public ResponseEntity<ApiResponse<List<EmployeeResponse>>> getExpiringEmployees(
            @RequestParam(defaultValue = "30") int days) {

        List<EmployeeResponse> employees = adminService.getExpiringEmployees(days)
                .stream()
                .map(EmployeeResponse::from)
                .toList();

        return ResponseEntity.ok(new ApiResponse<>(
                true,
                String.format("Found %d employees expiring within %d days", employees.size(), days),
                employees,
                LocalDateTime.now()
        ));
    }
}