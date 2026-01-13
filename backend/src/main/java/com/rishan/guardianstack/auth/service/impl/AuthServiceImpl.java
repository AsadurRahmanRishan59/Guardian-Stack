package com.rishan.guardianstack.auth.service.impl;

import com.rishan.guardianstack.auth.dto.request.LoginRequestDTO;
import com.rishan.guardianstack.auth.dto.request.PasswordResetRequest;
import com.rishan.guardianstack.auth.dto.request.SignUpRequestDTO;
import com.rishan.guardianstack.auth.dto.request.TokenRefreshRequest;
import com.rishan.guardianstack.auth.dto.response.LoginResponseDTO;
import com.rishan.guardianstack.auth.dto.response.UserResponse;
import com.rishan.guardianstack.auth.model.*;
import com.rishan.guardianstack.auth.repository.RoleRepository;
import com.rishan.guardianstack.auth.repository.UserRepository;
import com.rishan.guardianstack.auth.repository.VerificationTokenRepository;
import com.rishan.guardianstack.auth.service.*;
import com.rishan.guardianstack.core.exception.*;
import com.rishan.guardianstack.core.logging.AuditEventType;
import com.rishan.guardianstack.core.util.EmailPolicyValidator;
import com.rishan.guardianstack.core.util.JwtUtils;
import com.rishan.guardianstack.core.util.PasswordPolicyValidator;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicyValidator passwordPolicyValidator;
    private final EmailPolicyValidator emailPolicyValidator;
    private final VerificationServiceImpl verificationService;
    private final MailService mailService;
//    private final VerificationTokenRepository verificationTokenRepository;
    private final RefreshTokenService refreshTokenService;
    private final ELKAuditService elkAuditService;

    @Value("${app.security.account-lockout.max-attempts}")
    private int maxLoginAttempts;

    @Value("${app.security.account-lockout.duration-minutes}")
    private int lockoutDurationMinutes;

    // ==========================================
    // 1. REGISTRATION & VERIFICATION
    // ==========================================

    @Override
    @Transactional
    public LoginResponseDTO registerPublicUser(SignUpRequestDTO request, HttpServletRequest httpRequest) {
        Map<String, String> fieldErrors = new HashMap<>();
        validateSignUpRequest(request.username(), request.email(), request.password(), fieldErrors);

        if (userRepository.existsByEmail(request.email())) {
            elkAuditService.logFailure(
                    AuditEventType.SIGNUP_FAILED,
                    request.email(),
                    "Email already registered"
            );
            fieldErrors.put("email", "Email is already registered.");
        }

        if (!fieldErrors.isEmpty()) {
            throw new MultipleFieldValidationException(fieldErrors);
        }

        Role userRole = roleRepository.findByRoleName((AppRole.ROLE_USER))
                .orElseThrow(() -> new RuntimeException("Error: Default User Role not found in database."));

        User user = User.builder()
                .username(request.username())
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .roles(Collections.singleton(userRole))
                .enabled(false)
                .signUpMethod(SignUpMethod.EMAIL)
                .failedLoginAttempts(0)
                .accountLocked(false)
                .build();
        userRepository.save(user);

        elkAuditService.logSuccess(
                AuditEventType.SIGNUP_INITIATED,
                user,
                "Registration started, awaiting email verification"
        );

        String otp = verificationService.createEmailVerificationToken(user);
        mailService.sendVerificationEmail(user.getEmail(), user.getUsername(), otp);

        return new LoginResponseDTO(
                null,
                null,
                null,
                new UserResponse(
                        user.getUserId(),
                        user.getUsername(),
                        user.getEmail(),
                        user.isEnabled(),
                        List.of("ROLE_USER")
                )
        );
    }

    @Override
    @Transactional
    public LoginResponseDTO verifyAndLogin(String email, String otp, HttpServletRequest httpRequest) {
        validateEmailOnly(email);
        User user = verificationService.verifyEmailVerificationToken(email, otp);

        elkAuditService.logSuccess(
                AuditEventType.EMAIL_VERIFIED,
                user,
                "Email verified, first login session created"
        );

        UserDetailsImpl userDetails = UserDetailsImpl.build(user);
        String jwtToken = jwtUtils.generateJwtTokenFromEmail(userDetails);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getEmail(), null);

        return new LoginResponseDTO(
                jwtToken,
                refreshToken.getToken(),
                null,
                new UserResponse(
                        user.getUserId(),
                        user.getUsername(),
                        user.getEmail(),
                        user.isEnabled(),
                        user.getRoles().stream().map(r -> r.getRoleName().name()).toList()
                )
        );
    }

    @Override
    @Transactional
    public void resendVerificationCode(String email, HttpServletRequest httpRequest) {
        validateEmailOnly(email);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email, "email"));

        if (user.isEnabled()) {
            elkAuditService.logFailure(
                    AuditEventType.OTP_RESENT,
                    email,
                    "Account already verified"
            );
            throw new VerificationException("This account is already verified.");
        }

        String newOtp = verificationService.createEmailVerificationToken(user);
        mailService.sendVerificationEmail(user.getEmail(), user.getUsername(), newOtp);

        elkAuditService.logSuccess(
                AuditEventType.OTP_RESENT,
                user,
                "New OTP generated"
        );
    }

    // ==========================================
    // 2. SESSION MANAGEMENT (SIGN IN & REFRESH)
    // ==========================================

    @Override
    @Transactional
    public @NonNull LoginResponseDTO signin(@NonNull LoginRequestDTO loginRequestDTO, HttpServletRequest request) {
        String email = loginRequestDTO.email();
        User user = userRepository.findByEmail(email).orElse(null);

        if (user != null && user.isAccountLocked() && !user.isAccountNonLocked()) {
            elkAuditService.logFailure(
                    AuditEventType.LOGIN_FAILED,
                    email,
                    "Account locked until " + user.getLockedUntil()
            );

            throw new AccountLockedException(
                    String.format("Account is locked due to multiple failed login attempts. " +
                            "Please try again after %s", user.getLockedUntil()),
                    user.getLockedUntil()
            );
        }

        if (user != null) {
            if (!user.isAccountNonExpired()) {
                elkAuditService.logFailure(
                        AuditEventType.LOGIN_FAILED,
                        email,
                        "Account expired on " + user.getAccountExpiryDate()
                );

                throw new AccountExpiredException(
                        "Your account expired on " + user.getAccountExpiryDate() +
                                ". Please contact administrator.",
                        user.getAccountExpiryDate()
                );
            }

            if (!user.isCredentialsNonExpired()) {
                elkAuditService.logFailure(
                        AuditEventType.LOGIN_FAILED,
                        email,
                        "Password expired on " + user.getCredentialsExpiryDate()
                );
                throw new CredentialsExpiredException(
                        "Your password expired on " + user.getCredentialsExpiryDate() +
                                ". Please reset your password.",
                        user.getCredentialsExpiryDate()
                );
            }
        }
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequestDTO.email(),
                            loginRequestDTO.password()
                    )
            );
        } catch (DisabledException e) {
            elkAuditService.logFailure(
                    AuditEventType.LOGIN_FAILED,
                    email,
                    "Account is disabled"
            );
            throw e;
        } catch (BadCredentialsException e) {
            if (user != null) {
                handleFailedLogin(user, request);
            }
            elkAuditService.logFailure(
                    AuditEventType.LOGIN_FAILED,
                    email,
                    "Invalid credentials"
            );
            throw new BadCredentialsException("Invalid email or password");
        } catch (AuthenticationException e) {
            if (user != null) {
                handleFailedLogin(user, request);
            }

            elkAuditService.logFailure(
                    AuditEventType.LOGIN_FAILED,
                    email,
                    e.getMessage()
            );
            throw new BadCredentialsException("Authentication failed");
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);

        if (!(authentication.getPrincipal() instanceof UserDetailsImpl userDetails)) {
            throw new UserDetailsNotFoundException("User details not found");
        }

        if (user != null) {
            user.resetFailedAttempts();
            userRepository.save(user);
        }

        String jwtToken = Optional.ofNullable(jwtUtils.generateJwtTokenFromEmail(userDetails))
                .orElseThrow(() -> new JwtGenerationException("Failed to generate JWT token"));

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getEmail(), request);

        List<String> warnings = new ArrayList<>();
        if (user != null && user.isPasswordExpiringWithinDays(14)) {
            long daysLeft = user.getDaysUntilPasswordExpiry();


            warnings.add("Your password will expire in " + daysLeft + " days. Please update it soon.");

            elkAuditService.logSuccess(
                    AuditEventType.PASSWORD_EXPIRY_WARNING,
                    user,
                    daysLeft + " days remaining"
            );

            mailService.sendPasswordExpiryWarning(
                    user.getEmail(),
                    user.getUsername(),
                    daysLeft
            );

        }

        // Check for expiring account (warn if < 7 days)
        if (user != null && user.getDaysUntilAccountExpiry() > 0 &&
                user.getDaysUntilAccountExpiry() <= 7) {
            long daysLeft = user.getDaysUntilAccountExpiry();

            warnings.add("Your account access will expire in " + daysLeft + " days.");

            elkAuditService.logSuccess(
                    AuditEventType.ACCOUNT_EXPIRY_WARNING,
                    user,
                    daysLeft + " days remaining"
            );

            // Send warning email (async)
            mailService.sendAccountExpiryWarning(
                    user.getEmail(),
                    user.getUsername(),
                    daysLeft
            );
        }

        elkAuditService.logSuccess(
                AuditEventType.LOGIN_SUCCESS,
                user,
                "Login from " + parseDeviceName(request.getHeader("User-Agent"))
        );

        return new LoginResponseDTO(
                jwtToken,
                refreshToken.getToken(),
                warnings,
                new UserResponse(
                        Optional.ofNullable(userDetails.getId()).orElse(0L),
                        userDetails.getUsername(),
                        userDetails.getEmail(),
                        userDetails.isEnabled(),
                        userDetails.getAuthorities()
                                .stream()
                                .map(GrantedAuthority::getAuthority)
                                .toList()
                ));

    }


    @Override
    @Transactional
    public LoginResponseDTO refreshAccessToken(TokenRefreshRequest request, HttpServletRequest httpRequest) {
        String requestRefreshToken = request.getRefreshToken();

        return refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    UserDetailsImpl userDetails = UserDetailsImpl.build(user);
                    String newJwtToken = jwtUtils.generateJwtTokenFromEmail(userDetails);

                    // ROTATION with reuse detection
                    RefreshToken newRefreshToken = refreshTokenService.rotateRefreshToken(
                            requestRefreshToken,
                            user,
                            httpRequest
                    );

                    return new LoginResponseDTO(
                            newJwtToken,
                            newRefreshToken.getToken(),
                            null,
                            new UserResponse(
                                    user.getUserId(),
                                    user.getUsername(),
                                    user.getEmail(),
                                    user.isEnabled(),
                                    user.getRoles().stream().map(r -> r.getRoleName().name()).toList()
                            )
                    );
                })
                .orElseThrow(() -> new TokenRefreshException(requestRefreshToken,
                        "Refresh token is not in database!"));
    }

    @Override
    @Transactional
    public void logout(String refreshToken, HttpServletRequest request) {
        try {
            RefreshToken token = refreshTokenService.findByToken(refreshToken)
                    .orElseThrow(() -> new InvalidTokenException("Invalid refresh token"));

            User user = token.getUser();

            // Revoke the token
            refreshTokenService.revokeToken(refreshToken);

            elkAuditService.logSuccess(
                    AuditEventType.LOGOUT,
                    user,
                    "Logged out from current device"
            );

        } catch (InvalidTokenException e) {

            elkAuditService.logFailure(
                    AuditEventType.LOGOUT,
                    "unknown",
                    e.getMessage()
            );
            throw e;
        }
    }


    @Override
    @Transactional
    public void logoutAllDevices(String email, HttpServletRequest request) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        // Revoke all tokens for this user
        refreshTokenService.revokeAllUserTokens(user);

        elkAuditService.logSuccess(
                AuditEventType.LOGOUT_ALL_DEVICES,
                user,
                "Logged out from all devices"
        );
    }
// ==========================================
// 3. PASSWORD RECOVERY
// ==========================================

    @Override
    public void initiatePasswordReset(String email) {
        validateEmailOnly(email);
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        String otp = verificationService.createPasswordResetToken(user);
        mailService.sendPasswordResetEmail(user.getEmail(), user.getUsername(), otp);

        elkAuditService.logSuccess(
                AuditEventType.PASSWORD_RESET_INITIATED,
                user,
                "Password reset OTP sent"
        );
    }

    @Override
    @Transactional
    public void resetPassword(PasswordResetRequest request) {
        User user = userRepository.findByEmail(request.email()).orElseThrow(() -> new ResourceNotFoundException("User not found"));

        Map<String, String> fieldErrors = new HashMap<>();
        validateSignUpRequest(user.getEmail(), request.email(), request.newPassword(), fieldErrors);

        if (!fieldErrors.isEmpty()) {
            elkAuditService.logFailure(
                    AuditEventType.PASSWORD_RESET_FAILED,
                    request.email(),
                    "Validation failed"
            );
            throw new MultipleFieldValidationException(fieldErrors);
        }

        VerificationToken verificationToken = verificationTokenRepository
                .findByTokenAndTokenType(request.otp(), "PASSWORD_RESET")
                .orElseThrow(() -> {
                    elkAuditService.logFailure(
                            AuditEventType.PASSWORD_RESET_FAILED,
                            request.email(),
                            "Invalid OTP"
                    );
                    return new InvalidTokenException("Invalid reset code");
                });

        if (!verificationToken.getUser().getEmail().equals(request.email())) {
            elkAuditService.logFailure(
                    AuditEventType.PASSWORD_RESET_FAILED,
                    request.email(),
                    "OTP mismatch"
            );
            throw new InvalidTokenException("This code was not issued for this email address");
        }

        if (verificationToken.getExpiryDate().isBefore(LocalDateTime.now())) {
            verificationTokenRepository.delete(verificationToken);
            elkAuditService.logFailure(
                    AuditEventType.PASSWORD_RESET_FAILED,
                    request.email(),
                    "OTP expired"
            );
            throw new InvalidTokenException("Reset code has expired.");
        }

        user.setPassword(passwordEncoder.encode(request.newPassword()));
        user.resetFailedAttempts();

        userRepository.save(user);
        verificationTokenRepository.delete(verificationToken);
        refreshTokenService.revokeAllUserTokens(user);

        elkAuditService.logSuccess(
                AuditEventType.PASSWORD_RESET_COMPLETED,
                user,
                "Password reset successful, all sessions terminated"
        );
    }
    // ==========================================
    // 4. ACCOUNT SECURITY
    // ==========================================

    @Override
    @Transactional
    public void unlockAccount(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        user.resetFailedAttempts();
        userRepository.save(user);

        elkAuditService.logSuccess(
                AuditEventType.ACCOUNT_UNLOCKED,
                user,
                "Account unlocked by admin"
        );
    }

    private void handleFailedLogin(User user, HttpServletRequest request) {
        user.incrementFailedAttempts();

        if (user.getFailedLoginAttempts() >= maxLoginAttempts) {
            user.lockAccount(lockoutDurationMinutes);
            elkAuditService.logSuccess(
                    AuditEventType.ACCOUNT_LOCKED,
                    user,
                    String.format("Locked after %d failed attempts, unlock at: %s",
                            maxLoginAttempts, user.getLockedUntil())
            );
        }
        userRepository.save(user);
    }

// ==========================================
// 4. VALIDATION HELPERS
// ==========================================

    private void validateSignUpRequest(String username, String email, String password, Map<String, String> fieldErrors) {
        List<String> passwordErrors = passwordPolicyValidator.validate(password, username);
        if (!passwordErrors.isEmpty()) {
            fieldErrors.put("password", String.join(", ", passwordErrors));
        }

        List<String> emailErrors = emailPolicyValidator.validate(email);
        if (!emailErrors.isEmpty()) {
            fieldErrors.put("email", String.join(", ", emailErrors));
        }
    }

    private void validateEmailOnly(String email) {
        List<String> emailErrors = emailPolicyValidator.validate(email);
        if (!emailErrors.isEmpty()) {
            Map<String, String> errors = new HashMap<>();
            errors.put("email", String.join(", ", emailErrors));
            throw new MultipleFieldValidationException(errors);
        }
    }

    private String parseDeviceName(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) return "Unknown Device";
        if (userAgent.contains("Windows")) return "Windows PC";
        if (userAgent.contains("Mac")) return "Mac";
        if (userAgent.contains("iPhone")) return "iPhone";
        if (userAgent.contains("iPad")) return "iPad";
        if (userAgent.contains("Android")) return "Android Device";
        if (userAgent.contains("Linux")) return "Linux PC";
        return "Unknown Device";
    }
}
