package com.rishan.guardianstack.masteradmin.user.service.impl;

import com.rishan.guardianstack.auth.model.Role;
import com.rishan.guardianstack.auth.model.User;
import com.rishan.guardianstack.auth.repository.RoleRepository;
import com.rishan.guardianstack.auth.repository.UserRepository;
import com.rishan.guardianstack.core.exception.MultipleFieldValidationException;
import com.rishan.guardianstack.core.exception.ResourceNotFoundException;
import com.rishan.guardianstack.core.response.PaginatedResponse;
import com.rishan.guardianstack.core.util.EmailPolicyValidator;
import com.rishan.guardianstack.core.util.PasswordPolicyValidator;
import com.rishan.guardianstack.masteradmin.user.MasterAdminUserSpecification;
import com.rishan.guardianstack.masteradmin.user.dto.CreateUserRequestDTO;
import com.rishan.guardianstack.masteradmin.user.dto.MasterAdminUserDTO;
import com.rishan.guardianstack.masteradmin.user.dto.MasterAdminUserSearchCriteria;
import com.rishan.guardianstack.masteradmin.user.dto.MasterAdminUserViewDTO;
import com.rishan.guardianstack.masteradmin.user.mapper.MasterAdminUserMapper;
import com.rishan.guardianstack.masteradmin.user.service.MasterAdminUserService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@RequiredArgsConstructor
public class MasterAdminUserServiceImpl implements MasterAdminUserService {

    private final UserRepository userRepository;
    private final MasterAdminUserMapper mapper;
    private final RoleRepository roleRepository;
    private final EmailPolicyValidator emailPolicyValidator;
    private final PasswordPolicyValidator passwordPolicyValidator;

    /**
     * Retrieves a paginated list of users based on the provided search criteria.
     *
     * @param searchCriteria the criteria for searching and filtering users, including
     *                       pagination, sorting, and filter parameters.
     * @return a {@code PaginatedResponse} containing the list of users in the form of
     *         {@code MasterAdminUserViewDTO}, along with pagination and sorting metadata.
     */
    @Override
    public PaginatedResponse<MasterAdminUserViewDTO> getAllUsers(MasterAdminUserSearchCriteria searchCriteria) {
        Pageable pageable = PageRequest.of(
                searchCriteria.page(),
                searchCriteria.size(),
                createSort(searchCriteria.sortBy(), searchCriteria.sortDirection()));

        Specification<User> spec = MasterAdminUserSpecification.withFilters(searchCriteria);

        Page<User> userPage = userRepository.findAll(spec, pageable);
        List<MasterAdminUserViewDTO> userDTOS = userPage.getContent().stream().map(mapper::toMasterAdminUserViewDTO).toList();
        return PaginatedResponse.of(
                userDTOS,
                userPage.getNumber(),
                userPage.getSize(),
                userPage.getTotalElements(),
                userPage.getTotalPages(),
                userPage.hasNext(),
                userPage.hasPrevious(),
                searchCriteria.sortBy(),
                searchCriteria.sortDirection(),
                String.format("Found %d users", userPage.getTotalElements()));
    }

    /**
     * Retrieves a user by their unique identifier and converts it to a MasterAdminUserDTO.
     *
     * @param userId the unique identifier of the user to be retrieved
     * @return a MasterAdminUserDTO representing the user with the provided ID
     * @throws ResourceNotFoundException if no user is found with the provided ID
     */
    @Override
    public MasterAdminUserDTO getUserById(Long userId) {
        User user = userRepository.findById(userId).orElseThrow(() -> new ResourceNotFoundException(
                "User not found for id: " + userId
        ));
        return mapper.toMasterAdminUserDTO(user);
    }

    @Override
    @Transactional
    public Long createUser(CreateUserRequestDTO dto) {
        Map<String, String> fieldErrors = new HashMap<>();

        // 1. Full Validation for New User
        validateEmailOnly(dto.email(), fieldErrors);
        if (userRepository.existsByEmail(dto.email())) {
            fieldErrors.put("email", "Email already exists");
        }
        validatePassword(dto, fieldErrors);

        // 2. Validate Roles
        Set<Role> roles = validateRoles(dto.roleIds(), fieldErrors);

        if (!fieldErrors.isEmpty()) {
            throw new MultipleFieldValidationException(fieldErrors);
        }

        User user = mapper.toUser(dto, roles);
        User savedUser = userRepository.save(user);
        return savedUser.getUserId();
    }

    @Override
    @Transactional
    public Long updateUser(CreateUserRequestDTO dto, Long userId) {
        Map<String, String> fieldErrors = new HashMap<>();

        // 1. Find User
        User user = userRepository.findById(userId)
                .orElseThrow(() -> {
                    fieldErrors.put("userId", "No user found for id: " + userId);
                    return new MultipleFieldValidationException(fieldErrors);
                });

        // 2. Validate Email (Unique check excluding current user)
        validateEmailOnly(dto.email(), fieldErrors);
        if (userRepository.existsByEmail(dto.email()) && !user.getEmail().equals(dto.email())) {
            fieldErrors.put("email", "Email is already taken by another account");
        }

        // 3. Optional Password Validation (only if the password is provided/changed)
        if (dto.password() != null && !dto.password().isBlank()) {
            validatePassword(dto, fieldErrors);
        }

        // 4. Validate Roles
        Set<Role> roles = validateRoles(dto.roleIds(), fieldErrors);

        if (!fieldErrors.isEmpty()) {
            throw new MultipleFieldValidationException(fieldErrors);
        }

        // 5. Update and Save
        mapper.updateUser(user, dto, roles);
        userRepository.save(user);
        return user.getUserId();
    }

    // --- Helper Methods ---

    private Set<Role> validateRoles(List<Integer> roleIds, Map<String, String> fieldErrors) {
        Set<Role> roles = new HashSet<>();
        if (roleIds == null || roleIds.isEmpty()) {
            fieldErrors.put("roles", "At least one role must be assigned");
            return roles;
        }

        List<Integer> missingIds = new ArrayList<>();
        roleIds.forEach(id -> roleRepository.findById(id).ifPresentOrElse(roles::add, () -> missingIds.add(id)));

        if (!missingIds.isEmpty()) {
            fieldErrors.put("roles", "Invalid Role IDs: " + missingIds);
        }
        return roles;
    }

    private void validatePassword(CreateUserRequestDTO dto, Map<String, String> fieldErrors) {
        List<String> passwordErrors = passwordPolicyValidator.validate(dto.password(), dto.username());
        if (!passwordErrors.isEmpty()) {
            fieldErrors.put("password", String.join(", ", passwordErrors));
        }
    }

    private void validateEmailOnly(String email, Map<String, String> fieldErrors) {
        List<String> emailErrors = emailPolicyValidator.validate(email);
        if (!emailErrors.isEmpty()) {
            fieldErrors.put("email", String.join(", ", emailErrors));
        }
    }

    private Sort createSort(String sortBy, String sortDirection) {
        // Allowed sort fields for admin table
        Set<String> allowedTableSortFields = Set.of("userId", "userName", "createdAt", "updatedAt");

        String validatedSortBy = allowedTableSortFields.contains(sortBy) ? sortBy : "userName";

        Sort.Direction direction = "desc".equalsIgnoreCase(sortDirection)
                ? Sort.Direction.DESC
                : Sort.Direction.ASC;

        return Sort.by(direction, validatedSortBy);
    }
}