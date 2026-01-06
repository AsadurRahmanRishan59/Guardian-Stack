package com.rishan.guardianstack.masteradmin.user.mapper;

import com.rishan.guardianstack.auth.model.Role;
import com.rishan.guardianstack.auth.model.SignUpMethod;
import com.rishan.guardianstack.auth.model.User;
import com.rishan.guardianstack.masteradmin.user.dto.CreateUserRequestDTO;
import com.rishan.guardianstack.masteradmin.user.dto.MasterAdminUserDTO;
import com.rishan.guardianstack.masteradmin.user.dto.MasterAdminUserViewDTO;
import com.rishan.guardianstack.masteradmin.user.dto.UpdateUserRequestDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
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

    public void updateUser(User user, UpdateUserRequestDTO dto, Set<Role> roles) {
        // 1. Basic Identity & Access
        user.setUsername(dto.username());
        user.setEmail(dto.email());
        user.setRoles(roles);
        user.setEnabled(dto.enabled());

        // 2. Account Lifecycle (Contract/Subscription)
        user.setAccountExpiryDate(dto.accountExpiryDate());

        // 3. Password & Compliance Logic
        user.setMustChangePassword(dto.mustChangePassword());

        if (dto.password() != null && !dto.password().isBlank()) {
            // Encode new password and record the change time
            user.setPassword(passwordEncoder.encode(dto.password()));
            user.setLastPasswordChange(LocalDateTime.now());

            // Hierarchy for Credentials Expiry:
            // Priority 1: Specific Date > Priority 2: Validity Days > Priority 3: System Default
            if (dto.credentialsExpiryDate() != null) {
                user.setCredentialsExpiryDate(dto.credentialsExpiryDate());
            } else if (dto.passwordValidityDays() != null) {
                user.setPasswordExpiry(dto.passwordValidityDays());
            } else {
                user.setPasswordExpiry(tempPasswordExpiryDays);
            }
        } else {
            // If password ISN'T changing, but admin wants to manually extend the expiry date
            if (dto.credentialsExpiryDate() != null) {
                user.setCredentialsExpiryDate(dto.credentialsExpiryDate());
            }
        }

        // 4. Lockout & Security Logic
        // If the admin provides a lockedUntil date in the future, we force the lock state
        user.setLockedUntil(dto.lockedUntil());

        if (dto.lockedUntil() != null && dto.lockedUntil().isAfter(LocalDateTime.now())) {
            user.setAccountLocked(true);
        } else if (dto.lockedUntil() == null && user.isAccountLocked()) {
            // Manual Unlock: If the admin clears the date, we fully reset the lockout state
            user.resetFailedAttempts();
        }
    }
}
