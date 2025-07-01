package com.example.demo.services;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.EncryptionMethod;

@Service
public class JwtService {
  
  @Value("${jwe.shared-secret:}")
  private String jweSharedSecret;
  
  @Value("${jwe.enabled:false}")
  private boolean jweEnabled;
  
  @Value("${jwe.bypass-mode:false}")
  private boolean jweBypassMode;
  
  // Public key corresponding to the private key used for API tokens
  private final String apiTokenPublicKey = "-----BEGIN PUBLIC KEY-----\n" + //
      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvyNF4oxQTB3CaT6nJZqe\n" + //
      "NFI6Dz2j4a27iJfYnFOFojkw7+QBpIMNqFrvJe2RRerdPfS9lmaHruOMdLnU8RN2\n" + //
      "PH4zdknlkanyB9SLNHj9reqeMPUiq+sDGvTnOoTT7tA3al0WfGkyWR3eKfPETK97\n" + //
      "OKA9tH/33qfxUaSO3BhIOuOwVvJz6Jaq4TGO9QyZcNT7SLCKRqe5G8SVv2h/BTpi\n" + //
      "nL2Ijibs9uY1kyv+Pvv4tlHwtFD1HAPS6gl0Amfh2ldFYbRzZo3nKX15jM6PHxtC\n" + //
      "NLux663oX51WQL9KbA2qnqZ5yglK1RlXx6KyLwCaw/Kx1JKNC9SIvGNQzAXAo4Ly\n" + //
      "XQIDAQAB\n" + //
      "-----END PUBLIC KEY-----";
  public DecodedJWT decodeAndValidate(String token) {
    try {
      // Check if this is a JWE token (5 parts) or JWT token (3 parts)
      String[] tokenParts = token.split("\\.");
      
      if (tokenParts.length == 5) {
        // This is a JWE token
        if (jweBypassMode) {
          System.err.println("JWE BYPASS MODE ENABLED - Skipping decryption");
          System.err.println("Current token: JWE (5 parts) with algorithm: dir/A256GCM");
          System.err.println("To resolve this issue:");
          System.err.println("1. Configure Auth0 to return JWT tokens instead of JWE tokens");
          System.err.println("2. Check: https://localhost:8443/auth0/config-guide");
          System.err.println("3. See: AUTH0_JWT_SETUP.md for detailed instructions");
          System.err.println("4. Set jwe.bypass-mode=false once Auth0 is configured for JWT");
          return null;
        }
        
        // Attempt to decrypt JWE token
        String decryptedJwt = decryptJWE(token);
        if (decryptedJwt == null) {
          System.err.println("Cannot decrypt JWE token - incorrect shared secret");
          System.err.println("To resolve this issue:");
          System.err.println("1. Configure Auth0 to return JWT tokens instead (RECOMMENDED)");
          System.err.println("2. Check: https://localhost:8443/auth0/config-guide");
          System.err.println("3. Or find the correct Auth0 JWE shared secret");
          System.err.println("4. Temporary: Set jwe.bypass-mode=true to see configuration help");
          return null;
        }
        token = decryptedJwt;
      }
      
      // Now process as standard JWT
      DecodedJWT jwt = JWT.decode(token);
      String issuer = jwt.getIssuer();
      
      // Check if this is our independent API token
      if ("jwe-poc-independent-issuer".equals(issuer)) {
        return validateApiToken(token);
      }
      // Otherwise, validate as Auth0 token
      else {
        return validateAuth0Token(token);
      }
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }
  
  private String decryptJWE(String jweToken) {
    try {
      // Parse the JWE token to get header information
      JWEObject jweObject = JWEObject.parse(jweToken);
      
      // Get the key ID from the JWE header
      String keyId = jweObject.getHeader().getKeyID();
      JWEAlgorithm algorithm = jweObject.getHeader().getAlgorithm();
      EncryptionMethod encMethod = jweObject.getHeader().getEncryptionMethod();
      
      System.out.println("JWE Key ID: " + keyId);
      System.out.println("JWE Algorithm: " + algorithm);
      System.out.println("JWE Encryption Method: " + encMethod);
      
      // Handle direct key agreement (dir) algorithm with A256GCM
      if (JWEAlgorithm.DIR.equals(algorithm) && EncryptionMethod.A256GCM.equals(encMethod)) {
        System.out.println("Attempting to decrypt JWE token with dir/A256GCM");
        
        // For dir algorithm, we need a 256-bit (32 byte) shared secret key
        // In a real implementation, this would be retrieved from secure configuration
        // For now, we'll try common configurations or provide guidance
        
        String decryptedPayload = attemptDirectDecryption(jweObject);
        if (decryptedPayload != null) {
          System.out.println("Successfully decrypted JWE token");
          return decryptedPayload;
        }
      }
      
      // If decryption failed or unsupported algorithm
      System.err.println("JWE decryption failed: Unsupported algorithm or missing key");
      System.err.println("Algorithm: " + algorithm + ", Encryption: " + encMethod);
      System.err.println("For dir/A256GCM, a 256-bit shared secret key is required");
      System.err.println("Consider configuring Auth0 to return JWT tokens instead of JWE tokens");
      
      return null;
      
    } catch (Exception e) {
      System.err.println("Failed to parse JWE token: " + e.getMessage());
      e.printStackTrace();
      return null;
    }
  }
  
  private String attemptDirectDecryption(JWEObject jweObject) {
    // First try the configured shared secret
    if (jweEnabled && jweSharedSecret != null && !jweSharedSecret.isEmpty()) {
      try {
        byte[] sharedKey = prepare256BitKey(jweSharedSecret);
        if (sharedKey != null) {
          System.out.println("Attempting decryption with configured shared secret (length: " + sharedKey.length + " bytes)");
          DirectDecrypter decrypter = new DirectDecrypter(sharedKey);
          jweObject.decrypt(decrypter);
          return jweObject.getPayload().toString();
        }
      } catch (Exception e) {
        System.err.println("Decryption failed with configured shared secret: " + e.getMessage());
      }
    }
    
    // Fallback: try common patterns (for development/testing)
    String[] potentialKeys = {
        "your-256-bit-secret-key-here-XX", // Updated default from config
        "12345678901234567890123456789012", // Example 32-byte key
        "abcdefghijklmnopqrstuvwxyz123456",  // Another example
        "aaaabbbbccccddddeeeeffffgggghhhh"  // Hex-like pattern
    };
    
    System.out.println("Trying fallback keys for development/testing...");
    for (String keyString : potentialKeys) {
      try {
        byte[] sharedKey = prepare256BitKey(keyString);
        if (sharedKey != null) {
          DirectDecrypter decrypter = new DirectDecrypter(sharedKey);
          jweObject.decrypt(decrypter);
          System.out.println("Decryption successful with fallback key: " + keyString.substring(0, 8) + "...");
          return jweObject.getPayload().toString();
        }
      } catch (Exception e) {
        // Try next key
        continue;
      }
    }
    
    // If no keys worked, provide guidance
    System.err.println("Direct decryption failed with all attempted keys");
    System.err.println("To resolve:");
    System.err.println("1. Set jwe.shared-secret in application.properties with your Auth0 256-bit key");
    System.err.println("2. Ensure jwe.enabled=true in application.properties");
    System.err.println("3. Or configure Auth0 to use JWT tokens instead of JWE");
    System.err.println("Current config - JWE enabled: " + jweEnabled + ", Secret configured: " + 
                       (jweSharedSecret != null && !jweSharedSecret.isEmpty()));
    
    return null;
  }
  
  private byte[] prepare256BitKey(String keyString) {
    try {
      if (keyString == null || keyString.isEmpty()) {
        return null;
      }
      
      byte[] keyBytes = keyString.getBytes("UTF-8");
      
      if (keyBytes.length == 32) {
        // Perfect - already 256 bits
        return keyBytes;
      } else if (keyBytes.length < 32) {
        // Too short - pad with zeros or repeat pattern
        System.out.println("Key too short (" + keyBytes.length + " bytes), padding to 32 bytes");
        byte[] paddedKey = new byte[32];
        System.arraycopy(keyBytes, 0, paddedKey, 0, keyBytes.length);
        // Fill remaining bytes with pattern or zeros
        for (int i = keyBytes.length; i < 32; i++) {
          paddedKey[i] = (byte) ('0' + (i % 10)); // Fill with repeating digits
        }
        return paddedKey;
      } else {
        // Too long - truncate to 32 bytes
        System.out.println("Key too long (" + keyBytes.length + " bytes), truncating to 32 bytes");
        byte[] truncatedKey = new byte[32];
        System.arraycopy(keyBytes, 0, truncatedKey, 0, 32);
        return truncatedKey;
      }
    } catch (Exception e) {
      System.err.println("Failed to prepare 256-bit key: " + e.getMessage());
      return null;
    }
  }
  
  private DecodedJWT validateAuth0Token(String token) {
    JwkProvider provider = new UrlJwkProvider("https://sonatype-mtiq-test.us.auth0.com/");
    try {
      DecodedJWT jwt = JWT.decode(token);
      Jwk jwk = provider.get(jwt.getKeyId());
      Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
      JWTVerifier verifier = JWT.require(algorithm)
          .withIssuer("https://sonatype-mtiq-test.us.auth0.com/")
          .build();

      jwt = verifier.verify(token);
      return jwt;
    } catch (JWTVerificationException e) {
      // Invalid signature/claims
      e.printStackTrace();
    } catch (JwkException e) {
      // invalid JWT token
      e.printStackTrace();
    }
    return null;
  }
  
  private DecodedJWT validateApiToken(String token) {
    try {
      // Validate API token using our public key
      DecodedJWT jwt = decodeAndValidate_old(token, apiTokenPublicKey);
      
      if (jwt != null) {
        // Additional validation for independent API tokens
        String tokenType = jwt.getClaim("token_type").asString();
        if (!"independent_api_token".equals(tokenType)) {
          return null;
        }
        
        // Check if token is still active in our store
        String tokenId = jwt.getId();
        if (tokenId != null && !com.example.demo.controllers.ApiTokenController.isValidApiToken(tokenId)) {
          return null;
        }
      }
      
      return jwt;
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }

  public DecodedJWT decodeAndValidate_old(String token, String publicKey)
      throws NoSuchAlgorithmException, InvalidKeySpecException {

    publicKey = publicKey
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replaceAll(System.lineSeparator(), "")
        .replace("-----END PUBLIC KEY-----", "");

    byte[] publicKeyByteArray = Base64.getDecoder().decode(publicKey);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");

    try {
      RSAPublicKey rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyByteArray));
      Algorithm algorithm = Algorithm.RSA256(rsaPublicKey, null);
      JWTVerifier verifier = JWT.require(algorithm).build();
      DecodedJWT jwt = verifier.verify(token);
      return jwt;
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }

  public String createToken(Map<String, Object> claims, String privateKey)
      throws InvalidKeySpecException, NoSuchAlgorithmException {

    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    RSAPrivateKey rsaPrivateKey = null;

    privateKey = privateKey
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replaceAll(System.lineSeparator(), "")
        .replace("-----END PRIVATE KEY-----", "");

    byte[] privateKeyByteArray = Base64.getDecoder().decode(privateKey);
    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyByteArray);
    rsaPrivateKey = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);

    Algorithm algorithm = Algorithm.RSA256(null, rsaPrivateKey);
    String token = JWT.create().withPayload(claims).sign(algorithm);
    return token;
  }
}
