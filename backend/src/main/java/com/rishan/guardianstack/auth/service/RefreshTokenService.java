package com.rishan.guardianstack.auth.service;

import com.rishan.guardianstack.auth.model.RefreshToken;
import com.rishan.guardianstack.auth.model.User;
import jakarta.servlet.http.HttpServletRequest;

import java.util.Optional;

public interface RefreshTokenService {

    /**
     * Creates a new refresh token for the given user email
     */
    RefreshToken createRefreshToken(String email, HttpServletRequest request);

    RefreshToken rotateRefreshToken(String oldTokenString, User user, HttpServletRequest request);

    /**
     * Verifies that the refresh token has not expired
     */
    RefreshToken verifyExpiration(RefreshToken token);

    /**
     * Finds a refresh token by its token string
     */
    Optional<RefreshToken> findByToken(String token);

    /**
     * Revokes (deletes) a specific refresh token
     */
    void revokeToken(String token);

    /**
     * Revokes all refresh tokens for a specific user
     */
    void revokeAllUserTokens(User user);

    /**
     * Revokes all refresh tokens for a specific user by email
     */
    void revokeAllUserTokens(String email);

    /**
     * Cleans up expired refresh tokens
     */
    int cleanupExpiredTokens();
}