package com.example.demo.filters;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;
import java.util.logging.Logger;

import org.apache.http.HttpHeaders;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.demo.services.JwtService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private static final Logger log = Logger.getLogger(JwtAuthenticationFilter.class.getName());

    @Autowired
    private JwtService jwtService;

    private static final String[] EXCLUDED_PATHS = {
        "/login",
        "/publickey", 
        "/signin",
        "/",
        "/index.html",
        "/jwe/status",
        "/jwe/help",
        "/jwe/key-test",
        "/auth0/config-guide",
        "/api/tokens/create-independent"
    };

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
        String requestPath = request.getRequestURI();
        String method = request.getMethod();
        
        log.info("Processing request: " + method + " " + requestPath);

        // Skip authentication for excluded paths and static resources
        if (shouldSkipAuthentication(requestPath)) {
            log.info("Skipping authentication for path: " + requestPath);
            filterChain.doFilter(request, response);
            return;
        }

        // Extract Authorization header
        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            log.warning("Missing or invalid Authorization header for path: " + requestPath);
            sendUnauthorizedResponse(response, "Missing or invalid Authorization header");
            return;
        }

        try {
            // Extract token from "Bearer <token>"
            String token = authorizationHeader.substring("Bearer ".length()).trim();
            
            if (token.isEmpty()) {
                log.warning("Empty bearer token");
                sendUnauthorizedResponse(response, "Empty bearer token");
                return;
            }

            // Log token type for debugging
            String[] tokenParts = token.split("\\.");
            if (tokenParts.length == 5) {
                log.info("Processing JWE token (5 parts)");
            } else if (tokenParts.length == 3) {
                log.info("Processing JWT token (3 parts)");
            } else {
                log.warning("Invalid token format - expected 3 or 5 parts, got: " + tokenParts.length);
                sendUnauthorizedResponse(response, "Invalid token format");
                return;
            }

            // Validate JWT/JWE token
            DecodedJWT jwt = jwtService.decodeAndValidate(token);
            
            if (jwt == null) {
                log.warning("Token validation failed");
                sendUnauthorizedResponse(response, "Invalid token");
                return;
            }

            // Additional claims validation
            if (!validateTokenClaims(jwt)) {
                log.warning("JWT claims validation failed");
                sendUnauthorizedResponse(response, "Invalid token claims");
                return;
            }

            log.info("JWT token validated successfully for user: " + jwt.getSubject());
            
            // Store user information in request attributes for controllers to access
            request.setAttribute("jwt", jwt);
            request.setAttribute("user", jwt.getSubject());

            // Continue with the request
            filterChain.doFilter(request, response);

        } catch (Exception e) {
            log.severe("JWT validation error: " + e.getMessage());
            sendUnauthorizedResponse(response, "Token validation failed");
        }
    }

    private boolean shouldSkipAuthentication(String requestPath) {
        // Check exact matches for excluded paths
        for (String excludedPath : EXCLUDED_PATHS) {
            if (requestPath.equals(excludedPath)) {
                return true;
            }
        }
        
        // Skip static resources (CSS, JS, images, etc.)
        if (requestPath.startsWith("/static/") || 
            requestPath.endsWith(".css") || 
            requestPath.endsWith(".js") || 
            requestPath.endsWith(".png") || 
            requestPath.endsWith(".jpg") || 
            requestPath.endsWith(".jpeg") || 
            requestPath.endsWith(".gif") || 
            requestPath.endsWith(".ico") ||
            requestPath.endsWith(".woff") ||
            requestPath.endsWith(".woff2") ||
            requestPath.endsWith(".ttf")) {
            return true;
        }

        return false;
    }

    private boolean validateTokenClaims(DecodedJWT jwt) {
        try {
            Map<String, Claim> claims = jwt.getClaims();
            
            // Check token expiration
            Claim expClaim = claims.get("exp");
            if (expClaim != null) {
                long expirationTime = expClaim.asLong() * 1000; // Convert to milliseconds
                if (expirationTime < System.currentTimeMillis()) {
                    log.warning("Token has expired");
                    return false;
                }
            }

            // Check issuer - allow both Auth0 and our independent tokens
            Claim issuerClaim = claims.get("iss");
            if (issuerClaim != null) {
                String issuer = issuerClaim.asString();
                if (!"https://sonatype-mtiq-test.us.auth0.com/".equals(issuer) && 
                    !"jwe-poc-independent-issuer".equals(issuer)) {
                    log.warning("Invalid issuer: " + issuer);
                    return false;
                }
            }

            // Check audience (if present)
            Claim audienceClaim = claims.get("aud");
            if (audienceClaim != null) {
                String[] audiences = audienceClaim.asArray(String.class);
                if (audiences != null && audiences.length > 0) {
                    // For now, we'll be flexible with audience validation
                    // You can make this stricter based on your requirements
                    log.info("Token audience: " + Arrays.toString(audiences));
                }
            }

            return true;
            
        } catch (Exception e) {
            log.severe("Error validating token claims: " + e.getMessage());
            return false;
        }
    }

    private void sendUnauthorizedResponse(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        
        String jsonResponse = String.format(
            "{\"error\": \"Unauthorized\", \"message\": \"%s\", \"status\": %d}", 
            message, 
            HttpStatus.UNAUTHORIZED.value()
        );
        
        response.getWriter().write(jsonResponse);
        response.getWriter().flush();
    }
}