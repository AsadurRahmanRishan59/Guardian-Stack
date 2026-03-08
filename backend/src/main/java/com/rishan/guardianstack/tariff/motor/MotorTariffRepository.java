package com.rishan.guardianstack.tariff.motor;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

public interface MotorTariffRepository
        extends JpaRepository<MotorTariff, Long>, JpaSpecificationExecutor<MotorTariff> {
}
