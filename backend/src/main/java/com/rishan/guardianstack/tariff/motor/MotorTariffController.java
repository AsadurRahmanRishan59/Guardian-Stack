package com.rishan.guardianstack.tariff.motor;

import com.rishan.guardianstack.core.response.ApiResponse;
import com.rishan.guardianstack.tariff.motor.dto.MotorTariffDTO;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;

@RestController
@RequestMapping("/api/admin/tariffs/motor")
public class MotorTariffController {

    private final MotorTariffService service;

    public MotorTariffController(MotorTariffService service) {
        this.service = service;
    }

    // Get an motorTariff by tariffKey
    @GetMapping("/{tariffKey}")
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
}
