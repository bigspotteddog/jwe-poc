package com.example.demo;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

// import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

@Service
public class JwtService {
  // @Value("${JWT_SECRET_KEY}")
  private String encodedSecretKey;

  // @Value("${JWT_HMAC_KEY}")
  private String encodedHmacKey;

  public void setEncodedSecretKey(String encodedSecretKey) {
    this.encodedSecretKey = encodedSecretKey;
  }

  public void setEncodedHmacKey(String encodedHmacKey) {
    this.encodedHmacKey = encodedHmacKey;
  }

  public SignedJWT createVerifiedJwtToken(String encryptedJweToken)
      throws Exception {
    String decryptedJwtToken = decryptJweToken(encryptedJweToken);
    SignedJWT verifiedJwtToken = verifyJwtToken(decryptedJwtToken);
    return verifiedJwtToken;
  }

  public String createEncryptedJweToken(String subject, String issuer)
      throws KeyLengthException, JOSEException, NoSuchAlgorithmException, ParseException {
    String signedJwtToken = signJwtToken(subject, issuer);
    String encryptedJweToken = encryptJweToken(signedJwtToken);
    return encryptedJweToken;
  }

  public String createEncodedSecretKey() {
    SecureRandom random = new SecureRandom();
    byte[] sharedSecret = new byte[32];
    random.nextBytes(sharedSecret);
    String encodedSecrectKey = Base64.getEncoder().encodeToString(sharedSecret);
    return encodedSecrectKey;
  }

  public String createEncodedHmacKey() throws NoSuchAlgorithmException {
    // Get the expected key length for JWE enc "A128CBC-HS256"
    int keyBitLength = EncryptionMethod.A128CBC_HS256.cekBitLength();

    // Generate key
    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(keyBitLength);
    SecretKey key = keyGen.generateKey();

    String keyString = Base64.getEncoder().encodeToString(key.getEncoded());
    return keyString;
  }

  private SignedJWT verifyJwtToken(String decryptedJweToken) throws Exception {
    byte[] secretKey = decodeSecretKey(encodedSecretKey);
    SignedJWT signedJWT = SignedJWT.parse(decryptedJweToken);
    JWSVerifier verifier = new MACVerifier(secretKey);
    boolean verified = signedJWT.verify(verifier);
    if (!verified) {
      throw new Exception("Unauthorized");
    }
    return signedJWT;
  }

  private byte[] decodeSecretKey(String encodedSecretKey) {
    byte[] secretKey = Base64.getDecoder().decode(encodedSecretKey);
    return secretKey;
  }

  private String decryptJweToken(String signedJweToken)
      throws ParseException, JOSEException, KeyLengthException {
    SecretKey hmacKey = decodeHmacKey(encodedHmacKey);

    // Parse into JWE object again...
    JWEObject jweObject = JWEObject.parse(signedJweToken);

    // Decrypt
    jweObject.decrypt(new DirectDecrypter(hmacKey));

    // Get the plain text
    Payload payload = jweObject.getPayload();

    String decryptedJweToken = payload.toString();
    return decryptedJweToken;
  }

  private SecretKey decodeHmacKey(String encodedHmacKey) {
    byte[] decodedKey = decodeSecretKey(encodedHmacKey);
    SecretKey hmacKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    return hmacKey;
  }

  private String encryptJweToken(String signedJwtToken)
      throws NoSuchAlgorithmException, JOSEException, KeyLengthException, ParseException {

    SecretKey hmacKey = decodeHmacKey(encodedHmacKey);

    // Create the header
    JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256);

    // Set the plain text
    Payload payload = new Payload(signedJwtToken);

    // Create the JWE object and encrypt it
    JWEObject jweObject = new JWEObject(header, payload);
    jweObject.encrypt(new DirectEncrypter(hmacKey));

    // Serialise to compact JOSE form...
    String jweString = jweObject.serialize();

    return jweString;
  }

  private String signJwtToken(String subject, String issuer)
      throws KeyLengthException, JOSEException {
    byte[] secretKey = decodeSecretKey(encodedSecretKey);

    // Create HMAC signer
    JWSSigner signer = new MACSigner(secretKey);

    // Prepare JWT with claims set
    JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
        .subject(subject)
        .issuer(issuer)
        .expirationTime(new Date(new Date().getTime() + 60 * 1000))
        .build();

    SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

    // Apply the HMAC protection
    signedJWT.sign(signer);

    // Serialize to compact form, produces something like
    // eyJhbGciOiJIUzI1NiJ9.SGVsbG8sIHdvcmxkIQ.onO9Ihudz3WkiauDO2Uhyuz0Y18UASXlSc1eS0NkWyA
    String signedJwtToken = signedJWT.serialize();
    return signedJwtToken;
  }
}
