package com.rishan.guardianstack.tariff.motor;

import com.rishan.guardianstack.core.exception.DuplicateResourceException;
import com.rishan.guardianstack.core.exception.ResourceNotFoundException;
import com.rishan.guardianstack.core.response.PaginatedResponse;
import com.rishan.guardianstack.tariff.motor.dto.MotorTariffDTO;
import com.rishan.guardianstack.tariff.motor.dto.MotorTariffFullDTO;
import com.rishan.guardianstack.tariff.motor.dto.MotorTariffMasterAdminViewSearchCriteria;
import com.rishan.guardianstack.tariff.motor.dto.MotorTariffShortView;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.transaction.annotation.Transactional;


@Service
@RequiredArgsConstructor
public class MotorTariffService {

    private final MotorTariffRepository motorTariffRepository;
    private final MotorTariffMapper mapper;

    public PaginatedResponse<MotorTariffShortView> getMotorTariffsForAdminTable(
            MotorTariffMasterAdminViewSearchCriteria searchCriteria) {

        Pageable pageable = PageRequest.of(
                searchCriteria.page(),
                searchCriteria.size(),
                createSort(searchCriteria.sortBy(), searchCriteria.sortDirection()));

        Specification<MotorTariff> spec = MotorTariffMasterAdminViewSpecification
                .withFilters(searchCriteria);

        Page<MotorTariff> motorTariffPage = motorTariffRepository.findAll(spec, pageable);

        List<MotorTariffShortView> shortViews = motorTariffPage.getContent().stream().map(mapper::toMotorTariffShortView).toList();

        return PaginatedResponse.of(
                shortViews,
                motorTariffPage.getNumber(),
                motorTariffPage.getSize(),
                motorTariffPage.getTotalElements(),
                motorTariffPage.getTotalPages(),
                motorTariffPage.hasNext(),
                motorTariffPage.hasPrevious(),
                searchCriteria.sortBy(),
                searchCriteria.sortDirection(),
                String.format("Found %d motorTariffs", motorTariffPage.getTotalElements()));
    }

    // Get an motorTariff by tariffKey
    public MotorTariffDTO getMotorTariffById(Integer tariffKey) {
        MotorTariff motorTariff = motorTariffRepository.findById(tariffKey)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "MotorTariff not found with ID: " + tariffKey));

        return mapper.toMotorTariffDTO(motorTariff);
    }

    public MotorTariffFullDTO getFullMotorTariffById(Integer tariffKey) {
        MotorTariff motorTariff = motorTariffRepository.findById(tariffKey)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "MotorTariff not found with ID: " + tariffKey));
        return mapper.toMotorTariffFullDTO(motorTariff);
    }

    /**
     * Create a new Motor Tariff.
     * Checks for uniqueness against the composite key (Type, Group, Vehicle, Category).
     */
    @Transactional
    public MotorTariffDTO createMotorTariff(MotorTariffDTO dto) {

        motorTariffRepository.findByTariffTypeAndGroupOfVehicleAndTypeOfVehicleAndCategory(
                dto.tariffType(),
                dto.groupOfVehicle(),
                dto.typeOfVehicle(),
                dto.category()
        ).ifPresent(existing -> {
            throw new DuplicateResourceException("typeOfVehicle",
                    "Motor Tariff already exists with ID: " + existing.getTariffKey());
        });

        MotorTariff motorTariff = mapper.toMotorTariff(dto);
        MotorTariff savedTariff = motorTariffRepository.save(motorTariff);

        return mapper.toMotorTariffDTO(savedTariff);
    }

    /**
     * Update an existing Motor Tariff.
     * Ensures that the updated combination doesn't clash with another record.
     */
    @Transactional
    public MotorTariffDTO updateMotorTariff(Integer tariffKey, MotorTariffDTO dto) {

        MotorTariff existingTariff = motorTariffRepository.findById(tariffKey)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "MotorTariff not found with ID: " + tariffKey));

        motorTariffRepository.findByTariffTypeAndGroupOfVehicleAndTypeOfVehicleAndCategory(
                dto.tariffType(),
                dto.groupOfVehicle(),
                dto.typeOfVehicle(),
                dto.category()
        ).ifPresent(matched -> {
            if (!matched.getTariffKey().equals(tariffKey)) {
                throw new DuplicateResourceException("typeOfVehicle",
                        "This vehicle/category combination is already assigned to Tariff ID: " + matched.getTariffKey());
            }
        });

        mapper.toUpdatedMotorTariff(existingTariff, dto);
        MotorTariff updatedTariff = motorTariffRepository.save(existingTariff);
        return mapper.toMotorTariffDTO(updatedTariff);
    }

    // Delete a motor tariff by tariffKey
    public void deleteMotorTariff(Integer tariffKey) {
        if (!motorTariffRepository.existsById(tariffKey)) {
            throw new ResourceNotFoundException("MotorTariff not found with ID: " + tariffKey);
        }
        motorTariffRepository.deleteById(tariffKey);
    }

    public List<String> getHierarchy(String level, String tariffType, String groupOfVehicle, String typeOfVehicle) {
        MotorHierarchyLevel hLevel = MotorHierarchyLevel.fromString(level);

        // fallback
        // to tons
        // if no CC

        return switch (hLevel) {
            case TARIFF_TYPE -> motorTariffRepository.findDistinctTariffTypes();
            case GROUP_OF_VEHICLE -> motorTariffRepository.findDistinctGroupOfVehicles(tariffType);
            case TYPE_OF_VEHICLE -> motorTariffRepository.findDistinctTypeOfVehicle(tariffType, groupOfVehicle);
            case CATEGORY -> {
                List<String> categories = motorTariffRepository.findDistinctCategories(
                        tariffType, groupOfVehicle, typeOfVehicle);

                categories.sort(
                        Comparator.comparingDouble((String s) -> {
                                    double cc = extractCC(s);
                                    return cc == Double.MAX_VALUE ? extractTons(s) : cc; // fallback
                                    // to tons
                                    // if no CC
                                })
                                .thenComparing(s -> isUpto(s) ? 0 : 1));

                yield categories;
            }


            default -> throw new IllegalArgumentException("Invalid level: " + level);
        };
    }

    // Helper method to create Sort object

    /**
     * Create Sort object from sort parameters with validation
     */
    private Sort createSort(String sortBy, String sortDirection) {
        // Allowed sort fields for admin table
        Set<String> allowedTableSortFields = Set.of("tariffKey", "tariffType", "groupOfVehicle",
                "typeOfVehicle",
                "category");

        String validatedSortBy = allowedTableSortFields.contains(sortBy) ? sortBy : "tariffKey";

        Sort.Direction direction = "desc".equalsIgnoreCase(sortDirection)
                ? Sort.Direction.DESC
                : Sort.Direction.ASC;

        return Sort.by(direction, validatedSortBy);
    }

    private double extractCC(String str) {
        Matcher m = Pattern.compile("(\\d+(?:\\.\\d+)?)(?=\\s*CC)").matcher(str);
        if (m.find()) {
            return Double.parseDouble(m.group(1));
        }
        return Double.MAX_VALUE; // no CC found
    }

    private double extractTons(String str) {
        Matcher m = Pattern.compile("(\\d+(?:\\.\\d+)?)(?=\\s*ton)", Pattern.CASE_INSENSITIVE).matcher(str);
        if (m.find()) {
            return Double.parseDouble(m.group(1));
        }
        return Double.MAX_VALUE; // no tons found
    }

    private boolean isUpto(String str) {
        return str.toLowerCase().contains("upto");
    }

}
