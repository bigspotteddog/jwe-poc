package com.example.demo.controllers;

import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Controller;

@Controller
public class ApiTokenController {
    // In-memory store for API tokens (in production, use a database)
    private static final Map<String, ApiTokenInfo> activeTokens = new ConcurrentHashMap<>();


    // Helper method to validate API tokens (can be used by the filter)
    public static boolean isValidApiToken(String tokenId) {
        ApiTokenInfo tokenInfo = activeTokens.get(tokenId);
        if (tokenInfo == null) {
            return false;
        }
        
        // Check if token has expired
        return tokenInfo.getExpiresAt().after(new Date());
    }

    // Helper method to get token info
    public static ApiTokenInfo getTokenInfo(String tokenId) {
        return activeTokens.get(tokenId);
    }

    // Helper method to revoke token
    public static void revokeToken(String tokenId) {
        activeTokens.remove(tokenId);
    }

    // Helper method to add token to store
    public static void addToken(String tokenId, ApiTokenInfo tokenInfo) {
        activeTokens.put(tokenId, tokenInfo);
    }

    // Inner class to store token metadata
    public static class ApiTokenInfo {
        private final String tokenId;
        private final String userSub;
        private final String userName;
        private final String userEmail;
        private final Date expiresAt;
        private final Date createdAt;

        public ApiTokenInfo(String tokenId, String userSub, String userName, String userEmail, Date expiresAt, Date createdAt) {
            this.tokenId = tokenId;
            this.userSub = userSub;
            this.userName = userName;
            this.userEmail = userEmail;
            this.expiresAt = expiresAt;
            this.createdAt = createdAt;
        }

        // Getters
        public String getTokenId() { return tokenId; }
        public String getUserSub() { return userSub; }
        public String getUserName() { return userName; }
        public String getUserEmail() { return userEmail; }
        public Date getExpiresAt() { return expiresAt; }
        public Date getCreatedAt() { return createdAt; }
    }
}