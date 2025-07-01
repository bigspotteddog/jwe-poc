package com.example.demo.controllers;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class JweConfigController {

    @GetMapping("/jwe/status")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getJweStatus() {
        Map<String, Object> status = new HashMap<>();
        
        status.put("jwe_support", "enabled");
        status.put("algorithm_support", "dir/A256GCM");
        status.put("current_state", "JWE dir/A256GCM decryption implemented with configurable shared secret");
        
        Map<String, Object> solutions = new HashMap<>();
        solutions.put("option_1", "Set jwe.shared-secret in application.properties with 256-bit key");
        solutions.put("option_2", "Configure Auth0 to return JWT tokens instead of JWE");
        solutions.put("option_3", "Use environment variable JWE_SHARED_SECRET for production");
        
        status.put("solutions", solutions);
        
        Map<String, Object> auth0Config = new HashMap<>();
        auth0Config.put("domain", "sonatype-mtiq-test.us.auth0.com");
        auth0Config.put("expected_token_format", "JWT (3 parts)");
        auth0Config.put("current_token_format", "JWE (5 parts)");
        auth0Config.put("jwks_endpoint", "https://sonatype-mtiq-test.us.auth0.com/.well-known/jwks.json");
        
        status.put("auth0_config", auth0Config);
        
        return ResponseEntity.ok(status);
    }
    
    @GetMapping("/jwe/help")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getJweHelp() {
        Map<String, Object> help = new HashMap<>();
        
        help.put("title", "JWE Token Configuration Help");
        help.put("description", "This application can handle both JWT and JWE tokens, but JWE decryption requires proper key configuration");
        
        Map<String, String> steps = new HashMap<>();
        steps.put("step_1", "Login to your Auth0 Dashboard");
        steps.put("step_2", "Navigate to Applications → [Your App] → Advanced Settings");
        steps.put("step_3", "Go to OAuth → JsonWebToken Signature Algorithm");
        steps.put("step_4", "Ensure 'RS256' is selected (not encrypted variants)");
        steps.put("step_5", "Check Application Type is set to 'Single Page Application'");
        steps.put("step_6", "Verify Token Endpoint Authentication Method");
        
        help.put("configuration_steps", steps);
        
        Map<String, String> alternatives = new HashMap<>();
        alternatives.put("jwt_only", "Configure application to receive only JWT tokens");
        alternatives.put("jwe_with_keys", "Implement proper JWE key management with private keys");
        alternatives.put("mixed_mode", "Support both JWT and JWE with fallback handling");
        
        help.put("implementation_options", alternatives);
        
        return ResponseEntity.ok(help);
    }
    
    @GetMapping("/jwe/key-test")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> testKeyConfiguration() {
        Map<String, Object> result = new HashMap<>();
        
        // Test various key configurations
        String[] testKeys = {
            "your-256-bit-secret-key-here-XX", // Default config
            "12345678901234567890123456789012", // 32 chars
            "abcdefghijklmnopqrstuvwxyz123456",  // 32 chars
            "short-key",                        // Too short
            "this-key-is-way-too-long-and-exceeds-32-characters" // Too long
        };
        
        Map<String, Map<String, Object>> keyResults = new HashMap<>();
        
        for (String key : testKeys) {
            Map<String, Object> keyInfo = new HashMap<>();
            try {
                byte[] keyBytes = key.getBytes("UTF-8");
                keyInfo.put("original_length", keyBytes.length);
                keyInfo.put("original_string", key.length() > 20 ? key.substring(0, 20) + "..." : key);
                
                // Test key preparation
                byte[] preparedKey = prepareTestKey(key);
                if (preparedKey != null) {
                    keyInfo.put("prepared_length", preparedKey.length);
                    keyInfo.put("valid_for_aes256", preparedKey.length == 32);
                } else {
                    keyInfo.put("preparation_failed", true);
                }
            } catch (Exception e) {
                keyInfo.put("error", e.getMessage());
            }
            
            keyResults.put("key_" + (keyResults.size() + 1), keyInfo);
        }
        
        result.put("key_tests", keyResults);
        result.put("requirement", "JWE dir/A256GCM requires exactly 32 bytes (256 bits)");
        result.put("recommendation", "Use a strong 32-character string for your shared secret");
        
        return ResponseEntity.ok(result);
    }
    
    @GetMapping("/auth0/config-guide")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getAuth0ConfigGuide() {
        Map<String, Object> guide = new HashMap<>();
        
        guide.put("current_issue", "Auth0 returning JWE tokens (5 parts) instead of JWT tokens (3 parts)");
        guide.put("error_seen", "AES/GCM/NoPadding decryption failed: Tag mismatch!");
        guide.put("cause", "Application attempting JWE decryption with incorrect shared secret");
        
        Map<String, String> quickFix = new HashMap<>();
        quickFix.put("step_1", "Login to Auth0 Dashboard (manage.auth0.com)");
        quickFix.put("step_2", "Go to Applications → [Your App] → Settings");
        quickFix.put("step_3", "Advanced Settings → OAuth tab");
        quickFix.put("step_4", "Set 'JsonWebToken Signature Algorithm' to 'RS256'");
        quickFix.put("step_5", "Disable any ID Token Encryption settings");
        quickFix.put("step_6", "Save changes and test");
        
        guide.put("quick_fix_steps", quickFix);
        
        Map<String, String> verification = new HashMap<>();
        verification.put("success_indicator", "Application logs should show 'Processing JWT token (3 parts)'");
        verification.put("current_logs", "Currently seeing 'Processing JWE token (5 parts)'");
        verification.put("test_endpoint", "Monitor /api/tokens/create requests in application logs");
        
        guide.put("verification", verification);
        
        Map<String, String> alternatives = new HashMap<>();
        alternatives.put("option_1", "Configure Auth0 for JWT tokens (RECOMMENDED)");
        alternatives.put("option_2", "Find Auth0's actual JWE shared secret and configure it");
        alternatives.put("option_3", "Contact Auth0 support for JWE configuration details");
        
        guide.put("alternatives", alternatives);
        
        guide.put("documentation", "See AUTH0_JWT_SETUP.md for detailed instructions");
        
        return ResponseEntity.ok(guide);
    }
    
    private byte[] prepareTestKey(String keyString) {
        try {
            if (keyString == null || keyString.isEmpty()) {
                return null;
            }
            
            byte[] keyBytes = keyString.getBytes("UTF-8");
            
            if (keyBytes.length == 32) {
                return keyBytes;
            } else if (keyBytes.length < 32) {
                byte[] paddedKey = new byte[32];
                System.arraycopy(keyBytes, 0, paddedKey, 0, keyBytes.length);
                for (int i = keyBytes.length; i < 32; i++) {
                    paddedKey[i] = (byte) ('0' + (i % 10));
                }
                return paddedKey;
            } else {
                byte[] truncatedKey = new byte[32];
                System.arraycopy(keyBytes, 0, truncatedKey, 0, 32);
                return truncatedKey;
            }
        } catch (Exception e) {
            return null;
        }
    }
}