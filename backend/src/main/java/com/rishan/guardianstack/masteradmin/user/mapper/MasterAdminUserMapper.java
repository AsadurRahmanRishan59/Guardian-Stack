package com.rishan.guardianstack.masteradmin.user.mapper;

import com.rishan.guardianstack.auth.model.Role;
import com.rishan.guardianstack.auth.model.User;
import com.rishan.guardianstack.masteradmin.user.dto.CreateUserRequestDTO;
import com.rishan.guardianstack.masteradmin.user.dto.MasterAdminUserDTO;
import com.rishan.guardianstack.masteradmin.user.dto.MasterAdminUserViewDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
@RequiredArgsConstructor
public class MasterAdminUserMapper {

    private final PasswordEncoder passwordEncoder;

    public User toUser(CreateUserRequestDTO dto, Set<Role> roles) {
        return User.builder()
                .username(dto.username())
                .email(dto.email())
                .password(passwordEncoder.encode(dto.password()))
                .accountNonLocked(dto.accountNonLocked())
                .accountNonExpired(dto.accountNonExpired())
                .credentialsNonExpired(dto.credentialsNonExpired())
                .enabled(dto.enabled())
                .credentialsExpiryDate(dto.credentialsExpiryDate())
                .accountExpiryDate(dto.accountExpiryDate())
                .roles(roles)
                .build();
    }

    public MasterAdminUserDTO toMasterAdminUserDTO(User user) {
        return new MasterAdminUserDTO(
                user.getUserId(),
                user.getUsername(),
                user.getEmail(),
                user.isAccountNonLocked(),
                user.isAccountNonExpired(),
                user.isCredentialsNonExpired(),
                user.isEnabled(),
                user.getCredentialsExpiryDate(),
                user.getAccountExpiryDate(),
                user.getSignUpMethod(),
                user.getRoles(),
                user.getCreatedAt(),
                user.getUpdatedAt(),
                user.getCreatedBy(),
                user.getUpdatedBy()
        );
    }

    public MasterAdminUserViewDTO toMasterAdminUserViewDTO(User user) {
        return new MasterAdminUserViewDTO(
                user.getUserId(),
                user.getUsername(),
                user.getEmail(),
                user.isAccountNonLocked(),
                user.isAccountNonExpired(),
                user.isEnabled(),
                user.getSignUpMethod(),
                user.getRoles(),
                user.getCreatedAt(),
                user.getUpdatedAt()
        );
    }

    public void updateUser(User user, CreateUserRequestDTO dto, Set<Role> roles) {
        user.setUsername(dto.username());
        if (dto.password() != null) user.setPassword(passwordEncoder.encode(dto.password()));
        user.setEmail(dto.email());
        user.setAccountNonLocked(dto.accountNonLocked());
        user.setAccountNonExpired(dto.accountNonExpired());
        user.setCredentialsNonExpired(dto.credentialsNonExpired());
        user.setEnabled(dto.enabled());
        user.setCredentialsExpiryDate(dto.credentialsExpiryDate());
        user.setAccountExpiryDate(dto.accountExpiryDate());
        user.setRoles(roles);
    }
}
