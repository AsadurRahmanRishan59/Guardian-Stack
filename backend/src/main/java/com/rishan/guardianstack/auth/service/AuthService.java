package com.rishan.guardianstack.auth.service;

import com.rishan.guardianstack.auth.dto.request.LoginRequestDTO;
import com.rishan.guardianstack.auth.dto.request.PasswordResetRequest;
import com.rishan.guardianstack.auth.dto.request.SignUpRequestDTO;
import com.rishan.guardianstack.auth.dto.response.LoginResponseDTO;

public interface AuthService {
    LoginResponseDTO registerPublicUser(SignUpRequestDTO request);

    LoginResponseDTO signin(LoginRequestDTO loginRequestDTO);

    LoginResponseDTO verifyAndLogin(String email, String otp);

    void resendVerificationCode(String email);

    void initiatePasswordReset(String email);
    void resetPassword(PasswordResetRequest request);
}