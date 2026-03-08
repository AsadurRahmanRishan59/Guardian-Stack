package com.rishan.guardianstack.tariff.motor;

import com.rishan.guardianstack.core.exception.DuplicateResourceException;
import com.rishan.guardianstack.core.exception.ResourceNotFoundException;
import com.rishan.guardianstack.core.response.PaginatedResponse;
import com.rishan.guardianstack.tariff.motor.dto.MotorTariffDTO;
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
    public MotorTariffDTO getMotorTariffById(Long tariffKey) {
        MotorTariff motorTariff = motorTariffRepository.findById(tariffKey)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "MotorTariff not found with ID: " + tariffKey));

        return mapper.toMotorTariffDTO(motorTariff);
    }

    // Create an motorTariff
    public Long createMotorTariff(MotorTariffDTO dto) {

        String tariffType = dto.tariffType();
        String groupOfVehicle = dto.groupOfVehicle();
        String typeOfVehicle = dto.typeOfVehicle();
        String category = dto.category();

        Optional<MotorTariff> existMotorTariff = motorTariffRepository
                .findByTariffTypeAndGroupOfVehicleAndTypeOfVehicleAndCategory(tariffType,
                        groupOfVehicle, typeOfVehicle,
                        category);
        if (existMotorTariff.isPresent()) {
            throw new DuplicateResourceException("typeOfVehicle",
                    "Motor Tariff already exist by ID: " + existMotorTariff.get().getTariffKey());
        }

        // if()

        MotorTariff motorTariff = motorTariffRepository.save(mapper.toMotorTariff(dto));
        return mapper.toMotorTariffDTO(motorTariff).tariffKey();
    }

    // Update an motorTariff by tariffKey
    public MotorTariffResponseDTO updateMotorTariff(Integer motorTariffKey, MotorTariffRequestDTO dto) {

        // 1. FETCH EXISTING Motor Tariff
        MotorTariff existingMotorTariff = motorTariffRepository.findById(motorTariffKey)
                .orElseThrow(
                        () -> new ResourceNotFoundException(
                                "MotorTariff not found with ID: " + motorTariffKey));

        // 2. Check if another record exists with the new values (excluding current
        // record)
        Optional<MotorTariff> duplicate = motorTariffRepository
                .findByTariffTypeAndGroupOfVehicleAndTypeOfVehicleAndCategory(
                        dto.tariffType(),
                        dto.groupOfVehicle(),
                        dto.typeOfVehicle(),
                        dto.category());

        // 3. If duplicate exists AND it's not the same record we're updating
        if (duplicate.isPresent() && !duplicate.get().getTariffKey().equals(motorTariffKey)) {
            throw new DuplicateResourceException("typeOfVehicle",
                    "MotorTariff with these attributes already exists with ID: "
                            + duplicate.get().getTariffKey());
        }

        // 2. MAP AND SAVE UPDATED AGENT
        MotorTariff updatedMotorTariff = mapper.toUpdatedMotorTariff(existingMotorTariff, dto);
        MotorTariff savedMotorTariff = motorTariffRepository.save(updatedMotorTariff);

        return mapper.toMotorTariffResponseDTO(savedMotorTariff);

    }

    // Update an motorTariff by tariffKey
    public MotorTariffResponseDTO updateMotorTariffRates(Integer motorTariffKey,
                                                         MotorTariffUpdateRateRequestDTO dto) {
        // 1. FETCH EXISTING Motor Tariff
        MotorTariff existingMotorTariff = motorTariffRepository.findById(motorTariffKey)
                .orElseThrow(
                        () -> new ResourceNotFoundException(
                                "MotorTariff not found with ID: " + motorTariffKey));

        // 2. UPDATE ONLY THE RATES using your existing method
        MotorTariff updatedMotorTariff = mapper.toUpdatedMotorTariffRate(existingMotorTariff, dto);
        MotorTariff savedMotorTariff = motorTariffRepository.save(updatedMotorTariff);

        return mapper.toMotorTariffResponseDTO(savedMotorTariff);
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

        List<String> result = switch (hLevel) {
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

        return result;
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
