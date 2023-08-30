package com.example.demo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Date;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import com.nimbusds.jwt.SignedJWT;

@SpringBootTest
public class JwtServiceTest {
  @Autowired
  private JwtService jwtService;

  @Test
  public void testJwtPlusJwe() throws Exception {
    // setup
    String encodedSecretKey = jwtService.createEncodedSecretKey();
    jwtService.setEncodedSecretKey(encodedSecretKey);

    String encodedHmacKey = jwtService.createEncodedHmacKey();
    jwtService.setEncodedHmacKey(encodedHmacKey);

    String subject = "replace.me@gmail.com";
    String issuer = "example.com";

    // test
    String encryptedJweToken = jwtService.createEncryptedJweToken(subject, issuer);
    SignedJWT verifiedJwtToken = jwtService.createVerifiedJwtToken(encryptedJweToken);

    // verify
    assertEquals(subject, verifiedJwtToken.getJWTClaimsSet().getSubject());
    assertEquals(issuer, verifiedJwtToken.getJWTClaimsSet().getIssuer());
    assertTrue(new Date().before(verifiedJwtToken.getJWTClaimsSet().getExpirationTime()));
  }
}