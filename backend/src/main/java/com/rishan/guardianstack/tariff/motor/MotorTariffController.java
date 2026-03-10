package com.rishan.guardianstack.tariff.motor;

import com.rishan.guardianstack.core.ratelimit.RateLimited;
import com.rishan.guardianstack.core.response.ApiResponse;
import com.rishan.guardianstack.tariff.motor.dto.MotorTariffDTO;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/tariff/motor")
public class MotorTariffController {

    private final MotorTariffService service;

    public MotorTariffController(MotorTariffService service) {
        this.service = service;
    }

    // Get an motorTariff by tariffKey
    @GetMapping("/{tariffKey}")
    @RateLimited(maxAttempts = 100, timeWindow = 1, unit = TimeUnit.MINUTES)
    public ResponseEntity<ApiResponse<MotorTariffDTO>> getMotorTariffById(
            @PathVariable Integer tariffKey) {
        MotorTariffDTO motorTariff = service.getMotorTariffById(tariffKey);
        return ResponseEntity.status(HttpStatus.OK).body(
                new ApiResponse<>(
                        true, motorTariff.tariffKey() + " retrieved successfully",
                        motorTariff,
                        LocalDateTime.now()

                ));
    }

    @GetMapping("/hierarchy")
    @RateLimited(maxAttempts = 200, timeWindow = 15, unit = TimeUnit.MINUTES)
    public ResponseEntity<ApiResponse<List<String>>> getHierarchy(
            @RequestParam String level,
            @RequestParam(required = false) String tariffType,
            @RequestParam(required = false) String groupOfVehicle,
            @RequestParam(required = false) String typeOfVehicle) {
        List<String> result = service.getHierarchy(level, tariffType, groupOfVehicle, typeOfVehicle);
        return ResponseEntity.ok(
                new ApiResponse<>(true, "Fetched hierarchy successfully", result, LocalDateTime.now()));

    }
}
