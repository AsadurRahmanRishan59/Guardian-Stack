package com.rishan.guardianstack.auth.service.impl;

import com.rishan.guardianstack.auth.dto.request.LoginRequestDTO;
import com.rishan.guardianstack.auth.dto.request.SignUpRequestDTO;
import com.rishan.guardianstack.auth.dto.response.LoginResponseDTO;
import com.rishan.guardianstack.auth.dto.response.UserResponse;
import com.rishan.guardianstack.auth.model.AppRole;
import com.rishan.guardianstack.auth.model.Role;
import com.rishan.guardianstack.auth.model.SignUpMethod;
import com.rishan.guardianstack.auth.model.User;
import com.rishan.guardianstack.auth.repository.RoleRepository;
import com.rishan.guardianstack.auth.repository.UserRepository;
import com.rishan.guardianstack.auth.service.AuthService;
import com.rishan.guardianstack.core.exception.BadCredentialsException;
import com.rishan.guardianstack.core.exception.JwtGenerationException;
import com.rishan.guardianstack.core.exception.MultipleFieldValidationException;
import com.rishan.guardianstack.core.exception.UserDetailsNotFoundException;
import com.rishan.guardianstack.core.util.EmailPolicyValidator;
import com.rishan.guardianstack.core.util.JwtUtils;
import com.rishan.guardianstack.core.util.PasswordPolicyValidator;
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

        // 1. Validate Password and Email format
        validateSignUpRequest(request, fieldErrors);

        // 2. Uniqueness Check (ONLY Email)
        if (userRepository.existsByEmail(request.email())) {
            fieldErrors.put("email", "Email is already registered. Please login.");
        }
        if (!fieldErrors.isEmpty()) {
            throw new MultipleFieldValidationException(fieldErrors);
        }

        // 3. Fetch Default Role (ROLE_USER)
        Role userRole = roleRepository.findByRoleName((AppRole.ROLE_USER))
                .orElseThrow(() -> new RuntimeException("Error: Default User Role not found in database."));

        // 4. Map to Entity and Save
        User user = User.builder()
                .username(request.username()) // Full Official Name
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .roles(Collections.singleton(userRole))
                .enabled(true) // Set to false later if implementing Email OTP
                .signUpMethod(SignUpMethod.EMAIL)
                .build();
        userRepository.save(user);

        // 5. Automatic Sign-in after successful registration
        return signin(new LoginRequestDTO(request.email(), request.password()));
    }

    @Override
    public @NonNull LoginResponseDTO signin(@NonNull LoginRequestDTO loginRequestDTO) {

        Authentication authentication;
        try {
            // Spring Security uses the 'email' as the principal 'username'
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequestDTO.email(),
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
                        userDetails.getEmail(),     // This is the identifier
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
        // Password validation
        List<String> passwordErrors = passwordPolicyValidator.validate(request.password(), request.email());
        if (!passwordErrors.isEmpty()) {
            fieldErrors.put("password", String.join(", ", passwordErrors));
        }

        // Email validation
        List<String> emailErrors = emailPolicyValidator.validate(request.email());
        if (!emailErrors.isEmpty()) {
            fieldErrors.put("email", String.join(", ", emailErrors));
        }
    }
}

