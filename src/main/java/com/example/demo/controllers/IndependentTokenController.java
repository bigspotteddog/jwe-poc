package com.example.demo.controllers;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.logging.Logger;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.server.ResponseStatusException;

import com.example.demo.services.JwtService;

@Controller
public class IndependentTokenController {
    private static final Logger log = Logger.getLogger(IndependentTokenController.class.getName());

    @Autowired
    private JwtService jwtService;

    // Our own private key - completely independent of Auth0
    private final String ourPrivateKey = "-----BEGIN PRIVATE KEY-----\n" + //
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC/I0XijFBMHcJp\n" + //
        "Pqclmp40UjoPPaPhrbuIl9icU4WiOTDv5AGkgw2oWu8l7ZFF6t099L2WZoeu44x0\n" + //
        "udTxE3Y8fjN2SeWRqfIH1Is0eP2t6p4w9SKr6wMa9Oc6hNPu0DdqXRZ8aTJZHd4p\n" + //
        "88RMr3s4oD20f/fep/FRpI7cGEg647BW8nPolqrhMY71DJlw1PtIsIpGp7kbxJW/\n" + //
        "aH8FOmKcvYiOJuz25jWTK/4++/i2UfC0UPUcA9LqCXQCZ+HaV0VhtHNmjecpfXmM\n" + //
        "zo8fG0I0u7HrrehfnVZAv0psDaqepnnKCUrVGVfHorIvAJrD8rHUko0L1Ii8Y1DM\n" + //
        "BcCjgvJdAgMBAAECggEALUg3wQOBbXr6aTEe6719AAO//gbaKbfdTy+8MVLnPKbE\n" + //
        "dXzEt9sVc/5xHEDzUwdgmVI/TR+mwvPlPW0eKev0rcGvQvWgVdlXfevoe8qzPM3x\n" + //
        "4sLcjzKq5mrBUh+QTwpUqpX5owlQFIVLMhCuf4VuUZzC6Z2MlVsfxHoSH0oAaLTK\n" + //
        "H8q3LC/VB/EdnLNSf1vkVIS2V02hjYoFHnsqCrK4sB8hwH+bqqEGKWI0JcjMBItG\n" + //
        "cmfh4/JusINuAVT/IIUPaLo63s+mJcPeQqO78/7MUXa0tjyZ08MoIu4WtbVxUSru\n" + //
        "1Lx4jKCDjlERZ307hdD5fX8GqBGlJSK/nH4JMZ2o0QKBgQDkRNYGfNP9Q3yZRvyf\n" + //
        "EisgtwdNgfcVq7rOuwRNsbIfCUaKHoX+8fBzT6dzAkohapFutU+sF3mRcNUsQzMb\n" + //
        "SfOzwBB9TSoVXv/Mw29O4H2Aqn85ztrNOELw+0JugjJx6W6qhYIqFOa90WUswW1l\n" + //
        "eIasiVNtYxxaGoUAUP05HhnDLQKBgQDWW6jJuTjTMCpBghKtxmN0S0wGDD7Bu18h\n" + //
        "T4gdsOzlwbFGBpOK8SRkFJxsI/nFGpIyWuekJIJuCr5fb6aJZHtczoPUDOQ8BIVZ\n" + //
        "i7f48y7Dva/v9DWCwFn/VwTr6Q/4kjFkQaZZBwvjYe1HF+qi/nR+o606uQ70v/xi\n" + //
        "gai+AQAp8QKBgGt9kr9ZVsYjWnAfQmRxvMdaCOFRuxWEWaJx5JPlgngk+QefWf/0\n" + //
        "1AKo1rRMtrXHphZY4Nyr7T40wN1oA4/tIgpZ/inTBWcs5g35Vdfx1IebQe/p3ZTX\n" + //
        "0oYB+4VoX/LONqOr3OCOGR33lcoeh7JJsDldLWEMU9SGOm0stiGIcB89AoGBAJ8u\n" + //
        "A8KA/DS/0LFCwVIwP4yNmc/n6fZ9iOA4qjC6QMFBO75vhcMo3UhAkgQwFvuKhsRE\n" + //
        "Az4+KmlDKym9xKLEbmN1rCmcxSPYi5n6ikyhcbnDs9HxvIbzBiH6Ydo6ATUqgukb\n" + //
        "Y0c7V1WsU8J2fTQ61xFvxGUWJYgUxXv1IvSt04xRAoGASWLzQcQwWjhVSnNLGbGW\n" + //
        "DDf90YtZCLhTBA8uBDiNUt0eGUAyPwLZDMZEALQxnGt4ZoCpjHP/HxC2TXGDt8Ug\n" + //
        "NgYeX2GWoFRSy+/Ce8OzyC1hUn0zmZeKyAnlzkh3+fl/eIkZwa8qtkVGsWoT34iJ\n" + //
        "/khCnTTbgAlLqXytkbXh0DM=\n" + //
        "-----END PRIVATE KEY-----";

    @PostMapping("/api/tokens/create-independent")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> createIndependentApiToken(@RequestBody Map<String, Object> userInfo) {
        try {
            log.info("Creating independent API token from Auth0 user data");

            // Extract Auth0 user information from frontend
            String userName = (String) userInfo.get("name");
            String userEmail = (String) userInfo.get("email");
            String userSub = (String) userInfo.get("sub");
            Boolean emailVerified = (Boolean) userInfo.get("email_verified");
            String userPicture = (String) userInfo.get("picture");

            log.info("Creating token for user: " + userName + " (" + userEmail + ")");

            // Create our own unique token ID
            String tokenId = UUID.randomUUID().toString();
            long now = System.currentTimeMillis() / 1000;
            long tokenExpiration = now + (30 * 24 * 60 * 60); // 30 days

            // Build claims using Auth0 user data but with our own structure
            Map<String, Object> tokenClaims = new HashMap<>();
            
            // Standard JWT claims
            tokenClaims.put("iss", "jwe-poc-independent-issuer");     // Our issuer
            tokenClaims.put("sub", userSub);                           // Auth0 user ID
            tokenClaims.put("aud", "jwe-poc-api");                     // Our API
            tokenClaims.put("iat", now);                               // Issued at
            tokenClaims.put("exp", tokenExpiration);                   // Expires
            tokenClaims.put("jti", tokenId);                           // Token ID
            
            // Custom claims from Auth0 user data
            tokenClaims.put("token_type", "independent_api_token");
            tokenClaims.put("user_name", userName);
            tokenClaims.put("user_email", userEmail);
            tokenClaims.put("user_picture", userPicture);
            tokenClaims.put("email_verified", emailVerified);
            tokenClaims.put("auth_provider", "auth0");
            tokenClaims.put("token_source", "independent_generation");
            
            // Custom scopes/permissions
            tokenClaims.put("scopes", new String[]{"api:read", "api:write", "profile:read"});
            tokenClaims.put("permissions", new String[]{"create:resources", "read:own_data", "update:profile"});
            
            // Additional metadata
            tokenClaims.put("created_by", "jwe-poc-application");
            tokenClaims.put("generation_method", "auth0_user_data_extraction");

            // Generate the token using OUR private key (completely independent of Auth0)
            String apiToken = jwtService.createToken(tokenClaims, ourPrivateKey);

            // Store token metadata for validation (using the same store as ApiTokenController)
            ApiTokenController.ApiTokenInfo tokenInfo = new ApiTokenController.ApiTokenInfo(
                tokenId,
                userSub,
                userName,
                userEmail,
                new Date(tokenExpiration * 1000),
                new Date()
            );
            // Add to the active tokens store
            ApiTokenController.addToken(tokenId, tokenInfo);

            log.info("Independent API token created successfully for user: " + userName);

            // Prepare response
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("api_token", apiToken);
            response.put("token_id", tokenId);
            response.put("expires_at", new Date(tokenExpiration * 1000));
            response.put("expires_in_days", 30);
            response.put("scopes", new String[]{"api:read", "api:write", "profile:read"});
            response.put("permissions", new String[]{"create:resources", "read:own_data", "update:profile"});
            Map<String, Object> userInfoMap = new HashMap<>();
            userInfoMap.put("name", userName);
            userInfoMap.put("email", userEmail);
            userInfoMap.put("sub", userSub);
            userInfoMap.put("email_verified", emailVerified);
            response.put("user_info", userInfoMap);
            response.put("token_type", "independent");
            response.put("generation_method", "auth0_user_data_extraction");
            response.put("issuer", "jwe-poc-independent-issuer");

            return ResponseEntity.ok(response);

        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            log.severe("Error creating independent API token: " + e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Token generation failed");
        } catch (Exception e) {
            log.severe("Unexpected error creating independent API token: " + e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Token generation failed");
        }
    }
}