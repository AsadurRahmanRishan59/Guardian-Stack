package com.rishan.guardianstack.tariff.motor;

import com.rishan.guardianstack.tariff.motor.dto.MotorTariffDTO;
import com.rishan.guardianstack.tariff.motor.dto.MotorTariffShortView;
import org.springframework.stereotype.Component;

@Component
public final class MotorTariffMapper {

    public MotorTariff toMotorTariff(MotorTariffDTO requestDTO) {
        if (requestDTO == null) {
            return null;
        }

        return MotorTariff.builder()
                .tariffType(requestDTO.tariffType())
                .groupOfVehicle(requestDTO.groupOfVehicle())
                .typeOfVehicle(requestDTO.typeOfVehicle())
                .category(requestDTO.category())
                .ownDpBasic(requestDTO.ownDpBasic())
                .fullInsValue(requestDTO.fullInsValue())
                .actLiability(requestDTO.actLiability())
                .fire(requestDTO.fire())
                .theft(requestDTO.theft())
                .cyclone(requestDTO.cyclone())
                .earthquake(requestDTO.earthquake())
                .isActive(requestDTO.isActive() != null ? requestDTO.isActive() : true)
                .build();
    }

    public MotorTariffDTO toMotorTariffDTO(MotorTariff entity) {
        if (entity == null) {
            return null;
        }

        return new MotorTariffDTO(
                entity.getTariffKey(),
                entity.getTariffType(),
                entity.getGroupOfVehicle(),
                entity.getTypeOfVehicle(),
                entity.getCategory(),
                entity.getOwnDpBasic(),
                entity.getFullInsValue(),
                entity.getActLiability(),
                entity.getFire(),
                entity.getTheft(),
                entity.getCyclone(),
                entity.getEarthquake(),
                entity.getIsActive()
        );
    }

    public MotorTariffShortView toMotorTariffShortView(MotorTariff entity) {
        if (entity == null) {
            return null;
        }

        return new MotorTariffShortView(
                entity.getTariffKey(),
                entity.getTariffType(),
                entity.getGroupOfVehicle(),
                entity.getTypeOfVehicle(),
                entity.getCategory(),
                entity.getOwnDpBasic(),
                entity.getFullInsValue(),
                entity.getActLiability(),
                entity.getIsActive()
        );
    }

    public MotorTariff toUpdatedMotorTariff(MotorTariff entity, MotorTariffDTO requestDTO) {
        if (entity == null || requestDTO == null) {
            return entity;
        }

        entity.setTariffType(requestDTO.tariffType());
        entity.setGroupOfVehicle(requestDTO.groupOfVehicle());
        entity.setTypeOfVehicle(requestDTO.typeOfVehicle());
        entity.setCategory(requestDTO.category());
        entity.setOwnDpBasic(requestDTO.ownDpBasic());
        entity.setFullInsValue(requestDTO.fullInsValue());
        entity.setActLiability(requestDTO.actLiability());
        entity.setFire(requestDTO.fire());
        entity.setTheft(requestDTO.theft());
        entity.setCyclone(requestDTO.cyclone());
        entity.setEarthquake(requestDTO.earthquake());

        if (requestDTO.isActive() != null) {
            entity.setIsActive(requestDTO.isActive());
        }

        return entity;
    }
}