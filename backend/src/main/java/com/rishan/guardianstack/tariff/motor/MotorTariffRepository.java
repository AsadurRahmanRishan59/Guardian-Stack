package com.rishan.guardianstack.tariff.motor;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;

public interface MotorTariffRepository
        extends JpaRepository<MotorTariff, Integer>, JpaSpecificationExecutor<MotorTariff> {

    Optional<MotorTariff> findByTariffTypeAndGroupOfVehicleAndTypeOfVehicleAndCategory(
            String tariffType, String groupOfVehicle, String typeOfVehicle, String category);

    @Query("SELECT DISTINCT m.tariffType FROM MotorTariff m ORDER BY m.tariffType ASC")
    List<String> findDistinctTariffTypes();

    @Query("SELECT DISTINCT m.groupOfVehicle FROM MotorTariff m WHERE m.tariffType = :tariffType ORDER BY m.groupOfVehicle ASC")
    List<String> findDistinctGroupOfVehicles(@Param("tariffType") String tariffType);

    @Query("SELECT DISTINCT m.typeOfVehicle FROM MotorTariff m WHERE m.tariffType = :tariffType AND m.groupOfVehicle = :groupOfVehicle ORDER BY m.typeOfVehicle ASC")
    List<String> findDistinctTypeOfVehicle(@Param("tariffType") String tariffType,
                                           @Param("groupOfVehicle") String groupOfVehicle);

    @Query("SELECT DISTINCT m.category FROM MotorTariff m WHERE m.tariffType = :tariffType AND m.groupOfVehicle = :groupOfVehicle AND m.typeOfVehicle = :typeOfVehicle ORDER BY m.category ASC")
    List<String> findDistinctCategories(@Param("tariffType") String tariffType,
                                        @Param("groupOfVehicle") String groupOfVehicle,
                                        @Param("typeOfVehicle") String typeOfVehicle);

    @Query("SELECT mt FROM MotorTariff mt WHERE " +
            "mt.tariffType = :tariffType AND " +
            "mt.groupOfVehicle = :groupOfVehicle AND " +
            "mt.typeOfVehicle = :typeOfVehicle AND " +
            "mt.category = :category AND " +
            "mt.ownDpBasic = :ownDpBasic AND " +
            "mt.fullInsValue = :fullInsValue AND " +
            "mt.actLiability = :actLiability AND " +
            "mt.fire = :fire AND " +
            "mt.theft = :theft AND " +
            "mt.cyclone = :cyclone AND " +
            "mt.earthquake = :earthquake AND " +
            "mt.isActive = true")
    Optional<MotorTariff> findByAllParameters(
            @Param("tariffType") String tariffType,
            @Param("groupOfVehicle") String groupOfVehicle,
            @Param("typeOfVehicle") String typeOfVehicle,
            @Param("category") String category,
            @Param("ownDpBasic") BigDecimal ownDpBasic,
            @Param("fullInsValue") BigDecimal fullInsValue,
            @Param("actLiability") BigDecimal actLiability,
            @Param("fire") BigDecimal fire,
            @Param("theft") BigDecimal theft,
            @Param("cyclone") BigDecimal cyclone,
            @Param("earthquake") BigDecimal earthquake);


}