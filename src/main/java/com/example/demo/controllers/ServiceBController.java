package com.example.demo.controllers;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.logging.Logger;

import org.apache.http.HttpHeaders;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.server.ResponseStatusException;

import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.demo.services.JwtService;
import com.google.gson.Gson;

import jakarta.servlet.http.HttpServletRequest;

@Controller
public class ServiceBController {
  private static final Logger log = Logger.getLogger(ServiceBController.class.getName());

  @Autowired
  private JwtService jwtService;

  public static Map<String, Object> records = new LinkedHashMap<>() {
    {
      this.put("bob_roberts", "Bob Roberts");
      this.put("bill_williams", "Bill Williams");
      this.put("tom_thomson", "Tom Thomson");
    }
  };

  @GetMapping("/records")
  @ResponseBody
  public String getRecord(@RequestParam String who, HttpServletRequest request)
      throws NoSuchAlgorithmException, InvalidKeySpecException, ClientProtocolException, IOException {
    log.info("Received request...");

    String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
    authorization = authorization.substring("Bearer ".length());

    HttpGet get = new HttpGet("http://localhost:8080/publickey");
    String publicKey = send(get);

    DecodedJWT jwt = jwtService.decodeAndValidate(authorization, publicKey);
    log.info("  from principal: " + jwt.getSubject());

    log.info("Verifying claims...");
    Map<String, Claim> claims = jwt.getClaims();
    if (claims.get("exp").asLong() * 1000 < System.currentTimeMillis()) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Unauthorized");
    }

    if (claims.get("roles") == null) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Unauthorized");
    }

    Claim claim = claims.get("roles");
    List<String> roles = claim.asList(String.class);
    if (!roles.contains("User.Read.All")) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Unauthorized");
    }
    log.info("  " + jwt.getSubject() + " has roles: " + String.join(", ", roles));

    String value = (String) records.get(who);

    if (value == null) {
      throw new HttpResponseException(404, "Not found");
    }

    log.info("Returning record for: " + who);

    Map<String, Object> map = new HashMap<>();
    map.put("name", value);
    return new Gson().toJson(map);
  }

  private String send(HttpUriRequest request) throws IOException, ClientProtocolException {
    try (CloseableHttpClient httpclient = HttpClients.createDefault()) {
      CloseableHttpResponse response = httpclient.execute(request);
      InputStream inputStream = response.getEntity().getContent();

      try (Scanner s = new Scanner(inputStream).useDelimiter("\\A")) {
        String result = s.hasNext() ? s.next() : "";
        return result;
      }
    }
  }
}
