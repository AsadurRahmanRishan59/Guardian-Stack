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
    private final VerificationTokenRepository verificationTokenRepository;
    private final RefreshTokenService refreshTokenService;
    //    private final AuthAuditService authAuditService;
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
//            authAuditService.logFailedEvent(
//                    "SIGNUP_FAILED",
//                    request.email(),
//                    "Attempted registration with existing email",
//                    authAuditService.getClientIp(httpRequest),
//                    authAuditService.getUserAgent(httpRequest)
//            );
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

        authAuditService.logEvent(
                "SIGNUP_INITIATED",
                user,
                true, // Success
                authAuditService.getClientIp(httpRequest), // You need to pass HttpServletRequest to the method
                authAuditService.getUserAgent(httpRequest),
                "Public self-registration started; awaiting OTP verification"
        );

        String otp = verificationService.createToken(user);
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

    /**
     * Verifies the provided email and one-time password (OTP), authenticates the user,
     * and generates a JWT token along with a refresh token for the session.
     *
     * @param email The email address of the user attempting to log in. This must adhere to
     *              the application's email format and validation policies.
     * @param otp   The one-time password (OTP) provided by the user for authentication.
     * @return A {@code LoginResponseDTO} object containing the JWT token, refresh token,
     * and user-specific details including user ID, username, email, enabled status,
     * and role names.
     */
    @Override
    @Transactional
    public LoginResponseDTO verifyAndLogin(String email, String otp, HttpServletRequest httpRequest) {
        validateEmailOnly(email);
        User user = verificationService.verifyToken(email, otp, httpRequest);

        authAuditService.logEvent(
                "EMAIL_VERIFIED_LOGIN",
                user,
                true,
                authAuditService.getClientIp(httpRequest),
                authAuditService.getUserAgent(httpRequest),
                "User successfully verified email via OTP and initiated first session"
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

    /**
     * Resends a verification code to the user associated with the specified email address.
     * If the user's account is already verified, an exception will be thrown.
     *
     * @param email the email address of the user to resend the verification code to.
     *              Must be a valid and existing email in the system.
     * @throws ResourceNotFoundException if no user is found with the specified email address.
     * @throws VerificationException     if the user's account is already verified.
     */
    @Override
    @Transactional
    public void resendVerificationCode(String email, HttpServletRequest httpRequest) { // Added request
        validateEmailOnly(email);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email, "email"));

        if (user.isEnabled()) {
            // Log this as a failed/invalid attempt to resend
            authAuditService.logFailedEvent(
                    "RESEND_OTP_FAILED",
                    email,
                    "Account already verified",
                    authAuditService.getClientIp(httpRequest),
                    authAuditService.getUserAgent(httpRequest)
            );
            throw new VerificationException("This account is already verified.");
        }

        String newOtp = verificationService.createToken(user);
        mailService.sendVerificationEmail(user.getEmail(), user.getUsername(), newOtp);

        // Log the successful generation of a new token
        authAuditService.logEvent(
                "RESEND_OTP_SUCCESS",
                user,
                true,
                authAuditService.getClientIp(httpRequest),
                authAuditService.getUserAgent(httpRequest),
                "New verification OTP sent to email"
        );
    }

    // ==========================================
    // 2. SESSION MANAGEMENT (SIGN IN & REFRESH)
    // ==========================================

    /**
     * Authenticates a user by verifying their credentials and returns a response containing
     * a JWT token, refresh token, and user details.
     *
     * @param loginRequestDTO an object containing the user's email and password for authentication
     * @return a {@code LoginResponseDTO} containing a JWT token, refresh token, and user details
     * @throws DisabledException            if the user's account is disabled
     * @throws BadCredentialsException      if the authentication fails due to invalid email or password
     * @throws UserDetailsNotFoundException if user details cannot be retrieved after authentication
     * @throws JwtGenerationException       if an error occurs while generating the JWT token
     */
    @Override
    @Transactional
    public @NonNull LoginResponseDTO signin(@NonNull LoginRequestDTO loginRequestDTO, HttpServletRequest request) {
        String email = loginRequestDTO.email();

        // Get user
        User user = userRepository.findByEmail(email).orElse(null);

        // Check account lockout BEFORE authentication attempt
        if (user != null && user.isAccountLocked() && !user.isAccountNonLocked()) {
            authAuditService.logFailedEvent(
                    "LOGIN",
                    email,
                    "Account is locked until " + user.getLockedUntil(),
                    authAuditService.getClientIp(request),
                    authAuditService.getUserAgent(request)
            );

            throw new AccountLockedException(
                    String.format("Account is locked due to multiple failed login attempts. " +
                            "Please try again after %s", user.getLockedUntil()),
                    user.getLockedUntil()
            );
        }

        if (user != null) {
            // Check account expiry
            if (!user.isAccountNonExpired()) {
                authAuditService.logFailedEvent(
                        "LOGIN",
                        email,
                        "Account has expired on " + user.getAccountExpiryDate(),
                        authAuditService.getClientIp(request),
                        authAuditService.getUserAgent(request)
                );

                throw new AccountExpiredException(
                        "Your account expired on " + user.getAccountExpiryDate() +
                                ". Please contact administrator.",
                        user.getAccountExpiryDate()
                );
            }

            // Check credentials expiry
            if (!user.isCredentialsNonExpired()) {
                authAuditService.logFailedEvent(
                        "LOGIN",
                        email,
                        "Password expired on " + user.getCredentialsExpiryDate(),
                        authAuditService.getClientIp(request),
                        authAuditService.getUserAgent(request)
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
            authAuditService.logFailedEvent(
                    "LOGIN",
                    email,
                    "Account is disabled",
                    authAuditService.getClientIp(request),
                    authAuditService.getUserAgent(request)
            );
            throw e;
        } catch (BadCredentialsException e) {
            // Increment failed attempts
            if (user != null) {
                handleFailedLogin(user, request);
            }
            authAuditService.logFailedEvent(
                    "LOGIN",
                    email,
                    "Invalid credentials",
                    authAuditService.getClientIp(request),
                    authAuditService.getUserAgent(request)
            );
            throw new BadCredentialsException("Invalid email or password");
        } catch (AuthenticationException e) {
            if (user != null) {
                handleFailedLogin(user, request);
            }

            authAuditService.logFailedEvent(
                    "LOGIN",
                    email,
                    e.getMessage(),
                    authAuditService.getClientIp(request),
                    authAuditService.getUserAgent(request)
            );
            throw new BadCredentialsException("Authentication failed");
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);

        if (!(authentication.getPrincipal() instanceof UserDetailsImpl userDetails)) {
            throw new UserDetailsNotFoundException("User details not found");
        }

        // Reset failed attempts on successful login
        if (user != null) {
            user.resetFailedAttempts();
            userRepository.save(user);
        }

        String jwtToken = Optional.ofNullable(jwtUtils.generateJwtTokenFromEmail(userDetails))
                .orElseThrow(() -> new JwtGenerationException("Failed to generate JWT token"));

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getEmail(), request);

        // Check for expiring password (warn if < 14 days)
        List<String> warnings = new ArrayList<>();
        if (user != null && user.isPasswordExpiringWithinDays(14)) {
            long daysLeft = user.getDaysUntilPasswordExpiry();

            log.warn("⚠️ Password expiring soon for user: {} ({} days left)",
                    user.getEmail(), daysLeft);
            warnings.add("Your password will expire in " + daysLeft + " days. Please update it soon.");

            // Send warning email (async)
            mailService.sendPasswordExpiryWarning(
                    user.getEmail(),
                    user.getUsername(),
                    daysLeft
            );
            authAuditService.logEvent(
                    "PASSWORD_EXPIRY_WARNING",
                    user,
                    true,
                    authAuditService.getClientIp(request),
                    authAuditService.getUserAgent(request),
                    "User warned: Password expires in " + user.getDaysUntilPasswordExpiry() + " days"
            );
        }

        // Check for expiring account (warn if < 7 days)
        if (user != null && user.getDaysUntilAccountExpiry() > 0 &&
                user.getDaysUntilAccountExpiry() <= 7) {
            long daysLeft = user.getDaysUntilAccountExpiry();

            log.warn("⚠️ Account expiring soon for user: {} ({} days left)",
                    user.getEmail(), daysLeft);
            warnings.add("Your account access will expire in " + daysLeft + " days.");
            // Send warning email (async)
            mailService.sendAccountExpiryWarning(
                    user.getEmail(),
                    user.getUsername(),
                    daysLeft
            );
        }
        // Audit successful login
        auditAuthEvent("LOGIN", user, request, "User logged in successfully");

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
        // ==========================================
        // NEW: ADD EXPIRY WARNINGS TO RESPONSE
        // ==========================================

        // You'd need to modify LoginResponseDTO to include warnings
        // Or use a separate warnings endpoint
    }

    /**
     * Refreshes the access token and generates a new refresh token for the user.
     * The old refresh token is verified for validity and expiration, after which
     * a new access token along with a new refresh token is provided.
     *
     * @param request the token refresh request containing the current refresh token
     * @return a {@code LoginResponseDTO} containing the new access token, new refresh token,
     * and user details
     * @throws TokenRefreshException if the refresh token is not found in the database or is invalid
     */
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

    /**
     * Logs out the user by revoking their refresh token and creating an audit log entry.
     *
     * @param refreshToken the refresh token to be revoked
     * @param request      the HTTP request containing client information for audit logging
     */
    @Override
    @Transactional
    public void logout(String refreshToken, HttpServletRequest request) {
        try {
            RefreshToken token = refreshTokenService.findByToken(refreshToken)
                    .orElseThrow(() -> new InvalidTokenException("Invalid refresh token"));

            User user = token.getUser();

            // Revoke the token
            refreshTokenService.revokeToken(refreshToken);

            // Log successful logout
            auditAuthEvent("LOGOUT", user, request, "User logged out successfully");

        } catch (InvalidTokenException e) {
            // Log failed logout attempt
            authAuditService.logFailedEvent(
                    "LOGOUT",
                    "unknown",
                    e.getMessage(),
                    authAuditService.getClientIp(request),
                    authAuditService.getUserAgent(request)
            );
            throw e;
        }
    }

    /**
     * Logs out the user from all devices by revoking all their refresh tokens.
     *
     * @param email   the email of the user
     * @param request the HTTP request containing client information for audit logging
     */
    @Override
    @Transactional
    public void logoutAllDevices(String email, HttpServletRequest request) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        // Revoke all tokens for this user
        refreshTokenService.revokeAllUserTokens(user);

        // Log the action
        auditAuthEvent("LOGOUT_ALL_DEVICES", user, request, "User logged out from all devices");
    }
// ==========================================
// 3. PASSWORD RECOVERY
// ==========================================

    /**
     * Initiates the password reset process for a user by generating a one-time password (OTP)
     * and sending it to the user's registered email address.
     *
     * @param email the email address of the user requesting the password reset
     * @throws IllegalArgumentException  if the provided email is invalid
     * @throws ResourceNotFoundException if no user is found with the specified email address
     */
    @Override
    public void initiatePasswordReset(String email) {
        validateEmailOnly(email);
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        String otp = verificationService.createPasswordResetToken(user);
        mailService.sendPasswordResetEmail(user.getEmail(), user.getUsername(), otp);
    }

    /**
     * Resets the user's password based on the provided password reset request. This method validates the
     * request, verifies the reset token, checks for expiry, and updates the user's password if all conditions
     * are met. After successfully resetting the password, the reset token is deleted to avoid reuse.
     *
     * @param request The password reset request containing the user's email, one-time password (OTP),
     *                and the new password to be set.
     *                - email: The email address of the user requesting the password reset.
     *                - otp: The one-time password or reset code sent to the user's email.
     *                - newPassword: The new password the user wants to set.
     * @throws ResourceNotFoundException If the user with the given email does not exist.
     * @throws InvalidTokenException     If the provided reset token is invalid, does not belong to the user's
     *                                   email, or has expired.
     */
    @Override
    @Transactional
    public void resetPassword(PasswordResetRequest request) {
        User user = userRepository.findByEmail(request.email()).orElseThrow(() -> new ResourceNotFoundException("User not found"));

        Map<String, String> fieldErrors = new HashMap<>();
        validateSignUpRequest(user.getEmail(), request.email(), request.newPassword(), fieldErrors);

        if (!fieldErrors.isEmpty()) throw new MultipleFieldValidationException(fieldErrors);

        VerificationToken verificationToken = verificationTokenRepository
                .findByTokenAndTokenType(request.otp(), "PASSWORD_RESET")
                .orElseThrow(() -> new InvalidTokenException("Invalid reset code"));

        if (!verificationToken.getUser().getEmail().equals(request.email())) {
            throw new InvalidTokenException("This code was not issued for this email address");
        }

        if (verificationToken.getExpiryDate().isBefore(LocalDateTime.now())) {
            verificationTokenRepository.delete(verificationToken);
            throw new InvalidTokenException("Reset code has expired. Please request a new one.");
        }


        user.setPassword(passwordEncoder.encode(request.newPassword()));

        // Reset failed login attempts when password is reset
        user.resetFailedAttempts();

        userRepository.save(user);
        verificationTokenRepository.delete(verificationToken);

        // Revoke all refresh tokens (force re-login with new password)
        refreshTokenService.revokeAllUserTokens(user);

        log.info("Password reset successful for user: {}", user.getEmail());
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

        log.info("Account unlocked for user: {}", email);
    }

    /**
     * Handles failed login attempt - increments counter and locks if needed
     */
    private void handleFailedLogin(User user, HttpServletRequest request) {
        user.incrementFailedAttempts();

        if (user.getFailedLoginAttempts() >= maxLoginAttempts) {
            user.lockAccount(lockoutDurationMinutes);
            log.warn("🔒 Account locked for user: {} after {} failed attempts",
                    user.getEmail(), maxLoginAttempts);

            authAuditService.logEvent(
                    "ACCOUNT_LOCKED",
                    user,
                    false,
                    authAuditService.getClientIp(request),
                    authAuditService.getUserAgent(request),
                    String.format("Account locked after %d failed login attempts", maxLoginAttempts)
            );
        }

        userRepository.save(user);
    }

// ==========================================
// 4. VALIDATION HELPERS
// ==========================================

    /**
     * Validates the sign-up request by checking the provided username, email, and password
     * against their respective validation policies. If validation errors are found, they are
     * added to the provided fieldErrors map.
     *
     * @param username    the username provided in the sign-up request
     * @param email       the email address provided in the sign-up request
     * @param password    the password provided in the sign-up request
     * @param fieldErrors a map where validation errors for each field are stored with field names as keys
     */
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

    /**
     * Validates the provided email address against predefined email policy rules.
     * If the email is invalid, an exception is thrown containing the validation errors.
     *
     * @param email the email address to be validated
     * @throws MultipleFieldValidationException if the email is invalid, containing a map of error messages
     */
    private void validateEmailOnly(String email) {
        List<String> emailErrors = emailPolicyValidator.validate(email);
        if (!emailErrors.isEmpty()) {
            Map<String, String> errors = new HashMap<>();
            errors.put("email", String.join(", ", emailErrors));
            throw new MultipleFieldValidationException(errors);
        }
    }

    /**
     * Helper to audit authentication events
     */
    private void auditAuthEvent(String eventType, User user, HttpServletRequest request, String message) {
        authAuditService.logEvent(
                eventType,
                user,
                true,
                authAuditService.getClientIp(request),
                authAuditService.getUserAgent(request),
                message
        );
    }
}
