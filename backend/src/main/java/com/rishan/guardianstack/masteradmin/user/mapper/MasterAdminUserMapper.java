package com.rishan.guardianstack.masteradmin.user.mapper;

import com.rishan.guardianstack.auth.model.Role;
import com.rishan.guardianstack.auth.model.SignUpMethod;
import com.rishan.guardianstack.auth.model.User;
import com.rishan.guardianstack.masteradmin.user.dto.CreateUserRequestDTO;
import com.rishan.guardianstack.masteradmin.user.dto.MasterAdminUserDTO;
import com.rishan.guardianstack.masteradmin.user.dto.MasterAdminUserViewDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
@RequiredArgsConstructor
public class MasterAdminUserMapper {

    private final PasswordEncoder passwordEncoder;

    @Value("${app.security.employee.temp-password-expiry-days}")
    private int tempPasswordExpiryDays;

    public User toUser(CreateUserRequestDTO dto, Set<Role> roles) {
        User user = User.builder()
                .username(dto.username())
                .email(dto.email())
                .password(passwordEncoder.encode(dto.password()))
                .enabled(dto.enabled())
                .signUpMethod(SignUpMethod.ADMIN_CREATED)
                .mustChangePassword(dto.mustChangePassword())
                .accountExpiryDate(dto.accountExpiryDate())
                .roles(roles)
                .build();

        if (dto.passwordValidityDays() != null) {
            user.setPasswordExpiry(dto.passwordValidityDays());
        } else user.setPasswordExpiry(tempPasswordExpiryDays);

        return user;
    }

    public MasterAdminUserDTO toMasterAdminUserDTO(User user) {
        return new MasterAdminUserDTO(
                // CORE IDENTITY
                user.getUserId(),
                user.getUsername(),
                user.getEmail(),
                user.getRoles(),
                user.getSignUpMethod(),

                // STATUS
                user.isEnabled(),
                user.isAccountNonLocked(),
                user.isAccountNonExpired(),
                user.isCredentialsNonExpired(),

                // SECURITY FORENSICS
                user.getFailedLoginAttempts(),
                user.getLastFailedLogin(),
                user.getLastSuccessfulLogin(),
                user.getLockedUntil(),

                // COMPLIANCE
                user.getAccountExpiryDate(),
                user.getCredentialsExpiryDate(),
                user.getLastPasswordChange(),
                user.isMustChangePassword(),

                // AUDIT
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
        user.setEnabled(dto.enabled());
        user.setMustChangePassword(dto.mustChangePassword());
        user.setAccountExpiryDate(dto.accountExpiryDate());
        user.setAccountNonLocked(dto.accountNonLocked());
        user.setAccountNonExpired(dto.accountNonExpired());
        user.setCredentialsNonExpired(dto.credentialsNonExpired());
        user.setCredentialsExpiryDate(dto.credentialsExpiryDate());
        user.setAccountExpiryDate(dto.accountExpiryDate());
        user.setRoles(roles);

        // Only update password if provided
        if (dto.password() != null && !dto.password().isBlank()) {
            user.setPassword(passwordEncoder.encode(dto.password()));
            if (dto.passwordValidityDays() != null) {
                user.setPasswordExpiry(dto.passwordValidityDays());
            } else {
                user.setPasswordExpiry(tempPasswordExpiryDays);
            }
        }
    }
}
