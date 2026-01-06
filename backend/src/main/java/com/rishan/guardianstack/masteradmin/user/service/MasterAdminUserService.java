package com.rishan.guardianstack.masteradmin.user.service;

import com.rishan.guardianstack.core.response.PaginatedResponse;
import com.rishan.guardianstack.masteradmin.user.dto.*;

public interface MasterAdminUserService {

    /**
     * Retrieves a paginated list of users based on the specified search criteria.
     *
     * @param criteria the {@code MasterAdminUserSearchCriteria} object containing filters,
     *                 search parameters, pagination, and sorting information
     * @return a {@code PaginatedResponse<MasterAdminUserViewDTO>} containing the list of
     *         users that match the criteria, pagination details, and other response metadata
     */
    PaginatedResponse<MasterAdminUserViewDTO> getAllUsers(MasterAdminUserSearchCriteria criteria);

    /**
     * Retrieves the details of a specific user by their unique identifier.
     *
     * @param userId the unique identifier of the user to be retrieved
     * @return a {@code MasterAdminUserDTO} containing the details of the user
     */
    MasterAdminUserDTO getUserById(Long userId);

    /**
     * Creates a new user with the provided details.
     *
     * @param dto the {@code CreateUserRequestDTO} containing the details of the user to be created
     * @return the unique identifier of the newly created user
     */
    Long createUser(CreateUserRequestDTO dto);

    /**
     * Updates the details of an existing user using the provided data transfer object.
     *
     * @param dto    the {@code CreateUserRequestDTO} containing the updated details of the user
     * @param userId the unique identifier of the user to be updated
     * @return the unique identifier of the updated user
     */
    Long updateUser(UpdateUserRequestDTO dto, Long userId);
}
