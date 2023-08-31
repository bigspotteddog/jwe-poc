package com.example.demo;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

@Service
public class JwtService {
  public DecodedJWT decodeAndValidate(String token, String publicKey)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    String publicKeyPEM = publicKey
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replaceAll(System.lineSeparator(), "")
        .replace("-----END PUBLIC KEY-----", "");

    byte[] publicKeyByteArray = Base64.getDecoder().decode(publicKeyPEM);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    RSAPublicKey rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyByteArray));

    Algorithm algorithm = Algorithm.RSA256(rsaPublicKey, null);
    JWTVerifier verifier = JWT.require(algorithm)
        .acceptLeeway(6 * 60 * 60 * 1000)
        .withClaim("iss", "https://sts.windows.net/439dd1b8-73b6-4ae0-903d-521f615914b3/")
        .build();
    DecodedJWT jwt = verifier.verify(token);
    return jwt;
  }
}
