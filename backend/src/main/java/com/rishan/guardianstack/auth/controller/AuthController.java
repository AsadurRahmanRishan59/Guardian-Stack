package com.rishan.guardianstack.auth.controller;

import com.rishan.digitalinsurance.core.exception.UserDetailsNotFoundException;
import com.rishan.digitalinsurance.core.response.ApiResponse;
import com.rishan.digitalinsurance.modules.auth.dto.request.LoginRequestDTO;
import com.rishan.digitalinsurance.modules.auth.dto.request.SignUpRequestDTO;
import com.rishan.digitalinsurance.modules.auth.dto.response.LoginResponseDTO;
import com.rishan.digitalinsurance.modules.auth.dto.response.UserResponse;
import com.rishan.digitalinsurance.modules.auth.service.AuthService;
import com.rishan.digitalinsurance.modules.auth.service.impl.UserDetailsImpl;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
@Validated
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/public/signup")
    public ResponseEntity<ApiResponse<LoginResponseDTO>> registerUser(@Valid @RequestBody SignUpRequestDTO signUpRequest) {

        return ResponseEntity.ok(new ApiResponse<>(
                true,
                "User registered successfully. You can now log in.",
                authService.registerPublicUser(signUpRequest),
                LocalDateTime.now()
        ));
    }

    @PostMapping("/public/login")
    public ResponseEntity<ApiResponse<LoginResponseDTO>> signin(@Valid @RequestBody LoginRequestDTO loginRequestDTO) {
        return ResponseEntity.status(HttpStatus.OK).body(
                new ApiResponse<>(
                        true, "Welcome " + loginRequestDTO.username() + " !", authService.signin(loginRequestDTO),
                        LocalDateTime.now()

                ));
    }

    @GetMapping("/me")
    public ResponseEntity<ApiResponse<UserResponse>> getCurrentUser(@AuthenticationPrincipal UserDetails userDetails) {


        if (userDetails == null) {
            throw new UserDetailsNotFoundException("User details not found");
        }

        UserDetailsImpl user = (UserDetailsImpl) userDetails;

        return ResponseEntity.status(HttpStatus.OK).body(
                new ApiResponse<>(
                        true, "User details retrieved", new UserResponse(
                        Optional.ofNullable(user.getId()).orElse(0L),   // safe id
                        user.getUsername(),
                        user.getEmail(),
                        user.isEnabled(),
                        user.getAuthorities()
                                .stream()
                                .map(GrantedAuthority::getAuthority)
                                .toList()
                ),
                        LocalDateTime.now()

                ));

    }
}
