package com.rishan.guardianstack.tariff.motor;

import java.util.ArrayList;
import java.util.List;

import com.rishan.guardianstack.tariff.motor.dto.MotorTariffMasterAdminViewSearchCriteria;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.util.StringUtils;

import jakarta.persistence.criteria.Predicate;

public class MotorTariffMasterAdminViewSpecification {

    public static Specification<MotorTariff> withFilters(MotorTariffMasterAdminViewSearchCriteria criteria) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            if (criteria.tariffKey() != null) {
                predicates.add(cb.equal(root.get("tariffKey"), criteria.tariffKey()));
            }

            if (StringUtils.hasText(criteria.tariffType())) {
                predicates
                        .add(cb.like(cb.lower(root.get("tariffType")),
                                "%" + criteria.tariffType().toLowerCase() + "%"));
            }
            if (StringUtils.hasText(criteria.groupOfVehicle())) {
                predicates
                        .add(cb.like(cb.lower(root.get("groupOfVehicle")),
                                "%" + criteria.groupOfVehicle().toLowerCase() + "%"));
            }
            if (StringUtils.hasText(criteria.typeOfVehicle())) {
                predicates
                        .add(cb.like(cb.lower(root.get("typeOfVehicle")),
                                "%" + criteria.typeOfVehicle().toLowerCase() + "%"));
            }
            if (StringUtils.hasText(criteria.category())) {
                predicates
                        .add(cb.like(cb.lower(root.get("category")), "%" + criteria.category().toLowerCase() + "%"));
            }

            if (criteria.isActive() != null) {
                predicates.add(cb.equal(root.get("isActive"), criteria.isActive()));
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }

}
