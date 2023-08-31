package com.example.demo;

import java.util.Base64;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Service;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.DefaultJwtSignatureValidator;

import static io.jsonwebtoken.SignatureAlgorithm.HS256;

@Service
public class JwtService {
  public String decodeJWTToken(String token, String secretKey) throws Exception {
    Base64.Decoder decoder = Base64.getUrlDecoder();

    String[] chunks = token.split("\\.");

    String header = new String(decoder.decode(chunks[0]));
    String payload = new String(decoder.decode(chunks[1]));

    String tokenWithoutSignature = chunks[0] + "." + chunks[1];
    String signature = chunks[2];

    SignatureAlgorithm sa = HS256;
    SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), sa.getJcaName());

    DefaultJwtSignatureValidator validator = new DefaultJwtSignatureValidator(sa, secretKeySpec);

    if (!validator.isValid(tokenWithoutSignature, signature)) {
      throw new Exception("Could not verify JWT token integrity!");
    }

    return header + " " + payload;
  }
}
