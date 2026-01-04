package com.rishan.guardianstack.auth.service;

import com.rishan.guardianstack.auth.dto.request.LoginRequestDTO;
import com.rishan.guardianstack.auth.dto.request.PasswordResetRequest;
import com.rishan.guardianstack.auth.dto.request.SignUpRequestDTO;
import com.rishan.guardianstack.auth.dto.request.TokenRefreshRequest;
import com.rishan.guardianstack.auth.dto.response.LoginResponseDTO;
import jakarta.servlet.http.HttpServletRequest;

public interface AuthService {

    // --- Registration & Verification ---

    /**
     * Registers a new public user in the system based on the provided signup request.
     * This method creates a new user account and returns an authentication response,
     * which includes a JWT token, a refresh token, and user details.
     *
     * @param request the signup request containing the user's information, such as username, email, and password.
     * @return a {@code LoginResponseDTO} containing the authentication details, including JWT token, refresh token,
     * and user profile information for the newly registered user.
     */
    LoginResponseDTO registerPublicUser(SignUpRequestDTO request);

    /**
     * Verifies the provided one-time password (OTP) associated with the given email address
     * and logs the user into the system if the verification is successful. If the OTP is
     * valid, a {@code LoginResponseDTO} is returned containing authentication details such
     * as a JWT token, refresh token, and user profile information.
     *
     * @param email the email address of the user attempting to log in
     * @param otp   the one-time password provided by the user for verification
     * @return a {@code LoginResponseDTO} containing the authentication details if the verification is successful
     */
    LoginResponseDTO verifyAndLogin(String email, String otp);

    /**
     * Resends the verification code to the specified email address. This method is typically
     * used when a user requests to receive a new verification code if they did not
     * receive the initial one or the previous code has expired.
     *
     * @param email the email address to which the verification code should be sent
     */
    void resendVerificationCode(String email);

    // --- Session Management ---

    /**
     * Authenticates the user based on the provided login credentials. This method verifies
     * the user's email and password, and if valid, generates and returns an authentication
     * response containing a JWT token, a refresh token, and user profile details.
     *
     * @param loginRequestDTO the login request containing the user's email and password
     * @return a {@code LoginResponseDTO} containing the authentication details, including the JWT token,
     * refresh token, and user profile information if the credentials are valid
     */
    LoginResponseDTO signin(LoginRequestDTO loginRequestDTO, HttpServletRequest request);

    /**
     * Refreshes the access token using the provided refresh token. This method validates the
     * refresh token and generates a new access token along with a new refresh token if the validation
     * is successful. The response includes the updated authentication tokens and user profile information.
     *
     * @param request the token refresh request containing the refresh token to be validated
     * @return a {@code LoginResponseDTO} containing the new access token, refresh token,
     * and updated user profile details after successful validation
     */
    LoginResponseDTO refreshAccessToken(TokenRefreshRequest request, HttpServletRequest httpRequest);

    /**
     * Logs out the user by revoking their refresh token.
     * This prevents the user from obtaining new access tokens.
     *
     * @param refreshToken the refresh token to be revoked
     * @param request      the HTTP request (for audit logging)
     */
    void logout(String refreshToken, HttpServletRequest request);

    /**
     * Logs out the user from all devices by revoking all their refresh tokens.
     * This is useful when a user suspects unauthorized access or wants to
     * end all active sessions.
     *
     * @param email   the email of the user
     * @param request the HTTP request (for audit logging)
     */
    void logoutAllDevices(String email, HttpServletRequest request);

    // --- Password Recovery ---

    /**
     * Initiates the process for resetting the user's password by generating a password reset token
     * and sending it to the specified email address. The email will include instructions on how
     * to reset the password along with the necessary information for verification.
     *
     * @param email the email address of the user requesting a password reset
     */
    void initiatePasswordReset(String email);

    /**
     * Completes the password reset process by validating the provided password reset request
     * and updating the user's password. The request must include the user's email address,
     * a valid one-time password (OTP), and a new password. If the validation is successful,
     * the user's password is updated in the system.
     *
     * @param request the password reset request containing the user's email address, OTP, and new password
     */
    void resetPassword(PasswordResetRequest request);

    // --- Account Security ---
    void unlockAccount(String email);
}