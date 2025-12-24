package com.rishan.guardianstack.auth.service.impl;

import com.rishan.digitalinsurance.core.exception.BadCredentialsException;
import com.rishan.digitalinsurance.core.exception.JwtGenerationException;
import com.rishan.digitalinsurance.core.exception.MultipleFieldValidationException;
import com.rishan.digitalinsurance.core.exception.UserDetailsNotFoundException;
import com.rishan.digitalinsurance.core.util.EmailPolicyValidator;
import com.rishan.digitalinsurance.core.util.JwtUtils;
import com.rishan.digitalinsurance.core.util.PasswordPolicyValidator;
import com.rishan.digitalinsurance.modules.auth.dto.request.LoginRequestDTO;
import com.rishan.digitalinsurance.modules.auth.dto.request.SignUpRequestDTO;
import com.rishan.digitalinsurance.modules.auth.dto.response.LoginResponseDTO;
import com.rishan.digitalinsurance.modules.auth.dto.response.UserResponse;
import com.rishan.digitalinsurance.modules.auth.model.AppRole;
import com.rishan.digitalinsurance.modules.auth.model.Role;
import com.rishan.digitalinsurance.modules.auth.model.SignUpMethod;
import com.rishan.digitalinsurance.modules.auth.model.User;
import com.rishan.digitalinsurance.modules.auth.repository.RoleRepository;
import com.rishan.digitalinsurance.modules.auth.repository.UserRepository;
import com.rishan.digitalinsurance.modules.auth.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicyValidator passwordPolicyValidator;
    private final EmailPolicyValidator emailPolicyValidator;

    public LoginResponseDTO registerPublicUser(SignUpRequestDTO request) {

        Map<String, String> fieldErrors = new HashMap<>();

        // 1 . Validate SignupRequest
        validateSignUpRequest(request, fieldErrors);

        // 2. Normalized Mobile Number (Standardizing for BD SMS Gateways)
        String normalizedMobile = normalizeBdMobile(request.mobileNumber());

        // 3. Unique Constraints Check
        checkUniqueness(request.email(), normalizedMobile, fieldErrors);

        if (!fieldErrors.isEmpty()) {
            throw new MultipleFieldValidationException(fieldErrors);
        }

        // 6. Fetch Default Role (ROLE_USER)
        Role userRole = roleRepository.findByRoleName((AppRole.ROLE_USER))
                .orElseThrow(() -> new RuntimeException("Error: Default User Role not found in database."));

        // 7. Map to Entity and Save
        User user = User.builder()
                .username(request.username()) // Full Official Name
                .email(request.email())
                .mobileNumber(normalizedMobile) // Stored as 8801XXXXXXXXX
                .password(passwordEncoder.encode(request.password()))
                .roles(Collections.singleton(userRole))
                .enabled(true)
                .accountNonLocked(true)
                .accountNonExpired(true)
                .credentialsNonExpired(true)
                .accountExpiryDate(null)       // The actual Date (NULL = No expiry)
                .credentialsExpiryDate(null)
                .signUpMethod(SignUpMethod.FORM)
                .build();

        userRepository.save(user);
        return signin(new LoginRequestDTO(normalizedMobile, request.password()));
    }

    @Override
    public @NonNull LoginResponseDTO signin(@NonNull LoginRequestDTO loginRequestDTO) {

        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequestDTO.username(),
                            loginRequestDTO.password()
                    )
            );
        } catch (org.springframework.security.core.AuthenticationException e) {
            throw new BadCredentialsException("Bad credentials");
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Safe cast
        if (!(authentication.getPrincipal() instanceof UserDetailsImpl userDetails)) {
            throw new UserDetailsNotFoundException("User details not found");
        }

        // JWT generation check
        String jwtToken = Optional.ofNullable(jwtUtils.generateJwtTokenFromUsername(userDetails))
                .orElseThrow(() -> new JwtGenerationException("Failed to generate JWT token"));

        return new LoginResponseDTO(
                jwtToken,
                new UserResponse(
                        Optional.ofNullable(userDetails.getId()).orElse(0L),   // safe id
                        userDetails.getUsername(),
                        userDetails.getEmail(),
                        userDetails.isEnabled(),
                        userDetails.getAuthorities()
                                .stream()
                                .map(GrantedAuthority::getAuthority)
                                .toList()
                ));
    }

    /**
     * Validate SignUpRequestDTO
     */
    private void validateSignUpRequest(SignUpRequestDTO request, Map<String, String> fieldErrors) {
        // 1. Password Policy Validation (Passay)
        List<String> passwordErrors = passwordPolicyValidator.validate(request.password(), request.username());
        if (!passwordErrors.isEmpty()) {
            StringBuilder errorBuilder = new StringBuilder();
            String delimiter = "";

            for (String error : passwordErrors) {
                errorBuilder.append(delimiter).append(error);
                delimiter = ", ";
            }

            fieldErrors.put("password", errorBuilder.toString());
        }

        // 2. Email Policy Validation (Optional field check)
        if (request.email() != null && !request.email().isBlank()) {
            List<String> emailErrors = emailPolicyValidator.validate(request.email());
            if (!emailErrors.isEmpty()) {
                StringBuilder errorBuilder = new StringBuilder();
                String delimiter = "";
                for (String error : emailErrors) {
                    errorBuilder.append(delimiter).append(error);
                    delimiter = ", ";
                }
                fieldErrors.put("email", errorBuilder.toString());
            }
        }

        // 3. Global Contact Presence Check (Rule: Email or Mobile must exist)
        if ((request.email() == null || request.email().isBlank()) && (request.mobileNumber() == null)) {
            fieldErrors.put("email", "Either a valid email or mobile number is required.");
            fieldErrors.put("mobileNumber", "Either a valid email or mobile number is required.");
        }
    }

    private void checkUniqueness(String email, String mobile, Map<String, String> fieldErrors) {

        if (email != null && !email.isBlank() && userRepository.existsByEmail(email)) {
            fieldErrors.put("email", "Email is already in use.");
        }
        if (mobile != null && userRepository.existsByMobileNumber(mobile)) {
            fieldErrors.put("mobileNumber", "Mobile number is already in use.");
        }
    }

    /**
     * Normalizes BD number to 8801XXXXXXXXX format using the same regex logic.
     */
    private String normalizeBdMobile(String mobile) {
        if (mobile == null || mobile.isBlank()) return null;

        // Regex to extract the local 11-digit part: (01[3-9]\d{8})
        Pattern pattern = Pattern.compile("^(?:\\+88|88)?(01[3-9]\\d{8})$");
        Matcher matcher = pattern.matcher(mobile.replaceAll("\\s+", "")); // remove spaces

        if (matcher.find()) {
            String localPart = matcher.group(1); // extracts 01XXXXXXXXX
            return "88" + localPart; // returns 8801XXXXXXXXX
        }
        return null;
    }


}

