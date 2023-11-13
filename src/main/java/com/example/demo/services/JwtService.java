package com.example.demo.services;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

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

@Service
public class JwtService {
  public DecodedJWT decodeAndValidate(String token) {
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
