package com.rishan.guardianstack.auth.service;

import com.rishan.digitalinsurance.modules.auth.dto.request.LoginRequestDTO;
import com.rishan.digitalinsurance.modules.auth.dto.request.SignUpRequestDTO;
import com.rishan.digitalinsurance.modules.auth.dto.response.LoginResponseDTO;

public interface AuthService {
    LoginResponseDTO registerPublicUser(SignUpRequestDTO request);

    LoginResponseDTO signin(LoginRequestDTO loginRequestDTO);

}