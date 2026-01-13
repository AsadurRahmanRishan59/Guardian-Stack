package com.rishan.guardianstack.auth.service;

import com.rishan.guardianstack.auth.dto.request.LoginRequestDTO;
import com.rishan.guardianstack.auth.dto.request.PasswordResetRequest;
import com.rishan.guardianstack.auth.dto.request.SignUpRequestDTO;
import com.rishan.guardianstack.auth.dto.request.TokenRefreshRequest;
import com.rishan.guardianstack.auth.dto.response.LoginResponseDTO;
import jakarta.servlet.http.HttpServletRequest;

public interface AuthService {

    // --- Registration & Verification ---

    LoginResponseDTO registerPublicUser(SignUpRequestDTO request,HttpServletRequest httpRequest);

    LoginResponseDTO verifyAndLogin(String email, String otp, HttpServletRequest httpRequest);


    void resendVerificationCode(String email, HttpServletRequest httpRequest);

    // --- Session Management ---

    LoginResponseDTO signin(LoginRequestDTO loginRequestDTO, HttpServletRequest request);

    LoginResponseDTO refreshAccessToken(TokenRefreshRequest request, HttpServletRequest httpRequest);

    void logout(String refreshToken, HttpServletRequest request);

    void logoutAllDevices(String email, HttpServletRequest request);

    // --- Password Recovery ---

    void initiatePasswordReset(String email);

    void resetPassword(PasswordResetRequest request);

    // --- Account Security ---
    void unlockAccount(String email);
}