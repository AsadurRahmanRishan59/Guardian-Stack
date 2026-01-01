package com.rishan.guardianstack.auth.controller;

import com.rishan.guardianstack.auth.dto.request.LoginRequestDTO;
import com.rishan.guardianstack.auth.dto.request.PasswordResetRequest;
import com.rishan.guardianstack.auth.dto.request.SignUpRequestDTO;
import com.rishan.guardianstack.auth.dto.request.TokenRefreshRequest;
import com.rishan.guardianstack.auth.dto.response.LoginResponseDTO;
import com.rishan.guardianstack.auth.dto.response.UserResponse;
import com.rishan.guardianstack.auth.service.AuthService;
import com.rishan.guardianstack.auth.service.impl.UserDetailsImpl;
import com.rishan.guardianstack.core.exception.UserDetailsNotFoundException;
import com.rishan.guardianstack.core.response.ApiResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
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
@RequestMapping("/auth")
@Validated
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/public/signup")
    public ResponseEntity<ApiResponse<LoginResponseDTO>> registerUser(@Valid @RequestBody SignUpRequestDTO signUpRequest) {
        LoginResponseDTO response = authService.registerPublicUser(signUpRequest);

        return ResponseEntity.ok(new ApiResponse<>(
                true,
                "Registration successful! Please check your email for a 6-digit verification code to activate your account.",
                response,
                LocalDateTime.now()
        ));
    }

    @PostMapping("/public/verify-otp")
    public ResponseEntity<ApiResponse<LoginResponseDTO>> verifyOtp(
            @RequestParam String email,
            @RequestParam String otp) {

        LoginResponseDTO response = authService.verifyAndLogin(email, otp);

        return ResponseEntity.ok(new ApiResponse<>(
                true,
                "Email verified and logged in successfully!",
                response,
                LocalDateTime.now()
        ));
    }

    @PostMapping("/public/signin")
    public ResponseEntity<ApiResponse<LoginResponseDTO>> signin(@Valid @RequestBody LoginRequestDTO loginRequestDTO) {
        LoginResponseDTO response = authService.signin(loginRequestDTO);
        return ResponseEntity.status(HttpStatus.OK).body(
                new ApiResponse<>(
                        true, "Welcome " + response.userResponse().username() + " !", response,
                        LocalDateTime.now()

                ));
    }

    @PostMapping("/public/resend-otp")
    public ResponseEntity<ApiResponse<String>> resendOtp(@RequestParam String email) {
        authService.resendVerificationCode(email);
        return ResponseEntity.ok(new ApiResponse<>(
                true,
                "A new verification code has been sent to your email.",
                "OTP_RESENT",
                LocalDateTime.now()
        ));
    }

    @PostMapping("/public/forgot-password")
    public ResponseEntity<ApiResponse<Void>> forgotPassword(@Email(message = "Invalid Email") @RequestParam String email) {
        authService.initiatePasswordReset(email);
        return ResponseEntity.ok(new ApiResponse<>(true, "Reset code sent to your email.", null, LocalDateTime.now()));
    }

    @PostMapping("/public/reset-password")
    public ResponseEntity<ApiResponse<Void>> resetPassword(@Valid @RequestBody PasswordResetRequest request) {
        authService.resetPassword(request);
        return ResponseEntity.ok(new ApiResponse<>(true, "Password has been reset successfully. Please login", null, LocalDateTime.now()));
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

    @PostMapping("/public/refresh")
    public ResponseEntity<ApiResponse<LoginResponseDTO>> refreshToken(@Valid @RequestBody TokenRefreshRequest request) {
        LoginResponseDTO response = authService.refreshAccessToken(request);

        return ResponseEntity.ok(new ApiResponse<>(
                true,
                "Token refreshed successfully",
                response,
                LocalDateTime.now()
        ));
    }
}