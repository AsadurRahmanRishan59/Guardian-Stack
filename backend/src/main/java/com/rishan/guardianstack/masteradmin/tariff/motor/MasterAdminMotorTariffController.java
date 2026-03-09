package com.rishan.guardianstack.masteradmin.tariff.motor;

import com.rishan.guardianstack.core.ratelimit.RateLimited;
import com.rishan.guardianstack.core.response.ApiResponse;
import com.rishan.guardianstack.core.response.PaginatedResponse;
import com.rishan.guardianstack.tariff.motor.MotorTariff;
import com.rishan.guardianstack.tariff.motor.MotorTariffService;
import com.rishan.guardianstack.tariff.motor.dto.MotorTariffDTO;
import com.rishan.guardianstack.tariff.motor.dto.MotorTariffFullDTO;
import com.rishan.guardianstack.tariff.motor.dto.MotorTariffMasterAdminViewSearchCriteria;
import com.rishan.guardianstack.tariff.motor.dto.MotorTariffShortView;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/master-admin/tariff/motor")
@RequiredArgsConstructor
@PreAuthorize("hasRole('MASTER_ADMIN')")
public class MasterAdminMotorTariffController {

    private final MotorTariffService service;

    // Lightweight MotorTariff Table for Admin
    @GetMapping
    @RateLimited(maxAttempts = 500, timeWindow = 1, unit = TimeUnit.HOURS)
    public ResponseEntity<PaginatedResponse<MotorTariffShortView>> getMotorTariffsForAdminTable(
            @Valid MotorTariffMasterAdminViewSearchCriteria criteria) {
        return ResponseEntity.ok(service.getMotorTariffsForAdminTable(criteria));
    }

    // Get an motorTariff by tariffKey
    @GetMapping("/{tariffKey}")
    @RateLimited(maxAttempts = 300, timeWindow = 1, unit = TimeUnit.HOURS)
    public ResponseEntity<ApiResponse<MotorTariffFullDTO>> getMotorTariffById(
            @PathVariable Integer tariffKey) {
        MotorTariffFullDTO motorTariff = service.getFullMotorTariffById(tariffKey);
        return ResponseEntity.status(HttpStatus.OK).body(
                new ApiResponse<>(
                        true, motorTariff.tariffKey() + " retrieved successfully",
                        motorTariff,
                        LocalDateTime.now()

                ));
    }

    // Create an motorTariff
    @PostMapping()
    @RateLimited(maxAttempts = 50, timeWindow = 1, unit = TimeUnit.HOURS)
    public ResponseEntity<ApiResponse<MotorTariffDTO>> createMotorTariff(
            @Valid @RequestBody MotorTariffDTO dto) {
        MotorTariffDTO motorTariff = service.createMotorTariff(dto);
        return ResponseEntity.status(HttpStatus.CREATED).body(
                new ApiResponse<>(
                        true, motorTariff.tariffKey() + " created successfully",
                        motorTariff,
                        LocalDateTime.now()));
    }

    // Update an motorTariff by tariffKey
    @PutMapping("/{tariffKey}")
    @RateLimited(maxAttempts = 50, timeWindow = 1, unit = TimeUnit.HOURS)
    public ResponseEntity<ApiResponse<MotorTariffDTO>> updateMotorTariff(
            @PathVariable Integer tariffKey,
            @Valid @RequestBody MotorTariffDTO dto) {
        MotorTariffDTO motorTariff = service.updateMotorTariff(tariffKey, dto);
        return ResponseEntity.status(HttpStatus.OK).body(
                new ApiResponse<>(
                        true, motorTariff.tariffKey() + " Updated successfully",
                        motorTariff,
                        LocalDateTime.now()));
    }

    // Delete an motorTariff
    @DeleteMapping("/{tariffKey}")
    @RateLimited(maxAttempts = 20, timeWindow = 1, unit = TimeUnit.HOURS)
    public ResponseEntity<ApiResponse<Void>> deleteMotorTariff(@PathVariable Integer tariffKey) {
        service.deleteMotorTariff(tariffKey);
        return ResponseEntity.ok(
                new ApiResponse<>(
                        true,
                        "Motor tariff deleted successfully",
                        null,
                        LocalDateTime.now()));
    }
}
