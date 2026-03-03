package com.rishan.guardianstack.masteradmin.role;

import com.rishan.guardianstack.auth.model.Role;
import com.rishan.guardianstack.auth.repository.RoleRepository;
import com.rishan.guardianstack.core.exception.ResourceNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class RoleService {
    private final RoleRepository roleRepository;

    public List<Role> getRoles() {
        List<Role> roles = roleRepository.findAll();
        if (roles.isEmpty()) {
            throw new ResourceNotFoundException("No roles found");
        }
        return roles;
    }
}