package com.rishan.guardianstack.masteradmin.user.service.impl;

import com.rishan.guardianstack.auth.model.Role;
import com.rishan.guardianstack.auth.model.SignUpMethod;
import com.rishan.guardianstack.auth.model.User;
import com.rishan.guardianstack.auth.repository.RoleRepository;
import com.rishan.guardianstack.auth.repository.UserRepository;
import com.rishan.guardianstack.core.exception.MultipleFieldValidationException;
import com.rishan.guardianstack.core.exception.ResourceNotFoundException;
import com.rishan.guardianstack.core.response.PaginatedResponse;
import com.rishan.guardianstack.core.util.EmailPolicyValidator;
import com.rishan.guardianstack.core.util.PasswordPolicyValidator;
import com.rishan.guardianstack.masteradmin.user.MasterAdminUserSpecification;
import com.rishan.guardianstack.masteradmin.user.dto.*;
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
     * {@code MasterAdminUserViewDTO}, along with pagination and sorting metadata.
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

        validateEmailUniqueness(dto.email(), null, fieldErrors);
        validatePasswordComplexity(dto.password(), dto.username(), fieldErrors);
        Set<Role> roles = resolveRolesByIds(dto.roleIds(), fieldErrors);

        if (!fieldErrors.isEmpty()) {
            throw new MultipleFieldValidationException(fieldErrors);
        }

        User user = mapper.toUser(dto, roles);
        return userRepository.save(user).getUserId();
    }

    @Override
    @Transactional
    public Long updateUser(UpdateUserRequestDTO dto, Long userId) {
        Map<String, String> fieldErrors = new HashMap<>();

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found for id: " + userId));
        validateEmailUniqueness(dto.email(), user.getUserId(), fieldErrors);
        if (dto.password() != null && !dto.password().isBlank()) {
            validatePasswordComplexity(dto.password(), dto.username(), fieldErrors);
        }
        Set<Role> roles = resolveRolesByIds(dto.roleIds(), fieldErrors);

        if (!fieldErrors.isEmpty()) {
            throw new MultipleFieldValidationException(fieldErrors);
        }

        mapper.updateUser(user, dto, roles);
        return userRepository.save(user).getUserId();
    }

    // --- Helper Methods ---

    private void validateEmailUniqueness(String email, Long currentUserId, Map<String, String> fieldErrors) {
        List<String> emailErrors = emailPolicyValidator.validate(email);
        if (!emailErrors.isEmpty()) {
            fieldErrors.put("email", String.join(", ", emailErrors));
            return;
        }

        userRepository.findByEmail(email).ifPresent(existingUser -> {
            if (!existingUser.getUserId().equals(currentUserId)) {
                fieldErrors.put("email", "Email is already in use");
            }
        });
    }

    private void validatePasswordComplexity(String password, String username, Map<String, String> fieldErrors) {
        if (password == null || password.isBlank()) {
            fieldErrors.put("password", "Password cannot be empty");
            return;
        }

        List<String> passwordErrors = passwordPolicyValidator.validate(password, username);
        if (!passwordErrors.isEmpty()) {
            fieldErrors.put("password", String.join(", ", passwordErrors));
        }
    }

    private Set<Role> resolveRolesByIds(Collection<Integer> roleIds, Map<String, String> fieldErrors) {
        if (roleIds == null || roleIds.isEmpty()) {
            fieldErrors.put("roleIds", "At least one role must be assigned");
            return Collections.emptySet();
        }

        Set<Role> foundRoles = new HashSet<>();
        List<Integer> missingIds = new ArrayList<>();

        for (Integer id : roleIds) {
            roleRepository.findById(id).ifPresentOrElse(
                    foundRoles::add,
                    () -> missingIds.add(id)
            );
        }

        if (!missingIds.isEmpty()) {
            fieldErrors.put("roleIds", "Invalid Role IDs: " + missingIds);
        }
        return foundRoles;
    }

    private Sort createSort(String sortBy, String sortDirection) {
        // Allowed sort fields for admin table
        Set<String> allowedTableSortFields = Set.of("userId", "username", "createdAt", "updatedAt");

        String validatedSortBy = allowedTableSortFields.contains(sortBy) ? sortBy : "username";

        Sort.Direction direction = "desc".equalsIgnoreCase(sortDirection)
                ? Sort.Direction.DESC
                : Sort.Direction.ASC;

        return Sort.by(direction, validatedSortBy);
    }

    public MasterAdminUserFilterOptions getFilterOptions() {
        List<Role> roles = roleRepository.findAll();
        List<SignUpMethod> signUpMethods = Arrays.stream(SignUpMethod.values()).toList();
        return MasterAdminUserFilterOptions.create(signUpMethods, roles)
                ;
    }
}