package com.cts.authentication.service;

import java.util.HashSet;
import java.util.Set;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Service to manage a blacklist of JWT tokens.
 * Tokens added to this service are considered invalidated and should not be accepted for authentication.
 */
@Service
public class JwtBlacklistService {

    private static final Logger logger = LoggerFactory.getLogger(JwtBlacklistService.class);

    // ✅ Stores blacklisted tokens
    private final Set<String> blacklistedTokens = new HashSet<>();

    /**
     * Invalidates a given JWT token by adding it to the blacklist.
     * Subsequent attempts to use this token for authentication will fail.
     *
     * @param token The JWT token string to invalidate.
     */
    public void invalidateToken(String token) {
        // ✅ Add token to blacklist
        blacklistedTokens.add(token);
        logger.info("Token blacklisted successfully.");
    }

    /**
     * Checks if a given JWT token is present in the blacklist.
     *
     * @param token The JWT token string to check.
     * @return true if the token is blacklisted, false otherwise.
     */
    public boolean isTokenBlacklisted(String token) {
        // ✅ Check if token is invalidated
        boolean isBlacklisted = blacklistedTokens.contains(token);
        if (isBlacklisted) {
            logger.warn("Attempt to use blacklisted token.");
        }
        return isBlacklisted;
    }
}