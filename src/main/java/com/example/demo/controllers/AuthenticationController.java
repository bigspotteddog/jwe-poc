package com.example.demo.controllers;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.logging.Logger;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.server.ResponseStatusException;

import com.example.demo.services.JwtService;

import jakarta.servlet.http.HttpServletRequest;

@Controller
public class AuthenticationController {
  private static final Logger log = Logger.getLogger(AuthenticationController.class.getName());

  private String publicKey = "-----BEGIN CERTIFICATE-----\r\n" + //
      "MIIDGDCCAgCgAwIBAgIIYTtOcA3IMukwDQYJKoZIhvcNAQELBQAwKjEoMCYGA1UE\r\n" + //
      "AxMfc29uYXR5cGUtbXRpcS10ZXN0LnVzLmF1dGgwLmNvbTAeFw0yMzAzMjkyMTM0\r\n" + //
      "MjdaFw0zNjEyMDUyMTM0MjdaMCoxKDAmBgNVBAMTH3NvbmF0eXBlLW10aXEtdGVz\r\n" + //
      "dC51cy5hdXRoMC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDZ\r\n" + //
      "jEWGuK2x9ZpnE6R6WEU21KEsWh2HhpABh3twl3lwBPefCAoUNCQP9sQpNx5n9b19\r\n" + //
      "XYBS8YEtsR9KZ9ZUHIkYAYQXOOZakSa2FR0EQVsqc8ZFf9vpVijcHmF97DM20E6F\r\n" + //
      "h09pcxRT+zlXon6clI4GRZMoWf62pJ8Op5VsgY8XQ9nhJsl0s6ZpIcUQaiW529Ce\r\n" + //
      "+7VUjOZzZ4PwAwTpPeqNmnpY60L4N+XqsSsnSFASt4YlgWexQuFUkCAENP0yOP9m\r\n" + //
      "CGHgGtqFq6WNTxu0j5ts3JZp1+nQvJ46fuUUdkixD4AkJdj7rPr08OUJ7Gp8oypH\r\n" + //
      "7A6O6nDmviX7h3IUlPLxAgMBAAGjQjBAMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0O\r\n" + //
      "BBYEFOxXCR6W2EYG6dHOyB8nTLoQk1GFMA4GA1UdDwEB/wQEAwIChDANBgkqhkiG\r\n" + //
      "9w0BAQsFAAOCAQEAaEAl6jl+DZanK8fQQZlW4BHDPqdcOHD49CbKkFhaaVCLFHZu\r\n" + //
      "S8ggeRPqxcGbWxyKp8ui2jqyqDmp0wbmJzGjS0CpdC+Jsq/J7Lu8RnmKnE5IY4x6\r\n" + //
      "BbX10doVTfJcS6CyJvZ5cg21Hjamk28TTjbr1J+F/cxDg1bJebRWFWgt59hC29AW\r\n" + //
      "MocauTQIFjBs7y0e5GLJO4ipoWpzbDILuRCmt7WR56jSsDQ3gFkfNzd6tixmUFHS\r\n" + //
      "HqD3l6kdCC5JNNxMbf6uP3hkK5VJRXczV5cBqg/QrgpgafNO4Spk3wIDmX45DbsQ\r\n" + //
      "M/4dYN5L5k0QlEEmfDKS8NTShCdLEy2H/Q6M5w==\r\n" + //
      "-----END CERTIFICATE-----";
  
  // private String publicKey = "-----BEGIN PUBLIC KEY-----\n" + //
  //     "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6S7asUuzq5Q/3U9rbs+P\n" + //
  //     "kDVIdjgmtgWreG5qWPsC9xXZKiMV1AiV9LXyqQsAYpCqEDM3XbfmZqGb48yLhb/X\n" + //
  //     "qZaKgSYaC/h2DjM7lgrIQAp9902Rr8fUmLN2ivr5tnLxUUOnMOc2SQtr9dgzTONY\n" + //
  //     "W5Zu3PwyvAWk5D6ueIUhLtYzpcB+etoNdL3Ir2746KIy/VUsDwAM7dhrqSK8U2xF\n" + //
  //     "CGlau4ikOTtvzDownAMHMrfE7q1B6WZQDAQlBmxRQsyKln5DIsKv6xauNsHRgBAK\n" + //
  //     "ctUxZG8M4QJIx3S6Aughd3RZC4Ca5Ae9fd8L8mlNYBCrQhOZ7dS0f4at4arlLcaj\n" + //
  //     "twIDAQAB\n" + //
  //     "-----END PUBLIC KEY-----";

  private String privateKey = "-----BEGIN PRIVATE KEY-----\n" + //
      "MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQDpLtqxS7OrlD/d\n" + //
      "T2tuz4+QNUh2OCa2Bat4bmpY+wL3FdkqIxXUCJX0tfKpCwBikKoQMzddt+ZmoZvj\n" + //
      "zIuFv9eploqBJhoL+HYOMzuWCshACn33TZGvx9SYs3aK+vm2cvFRQ6cw5zZJC2v1\n" + //
      "2DNM41hblm7c/DK8BaTkPq54hSEu1jOlwH562g10vcivbvjoojL9VSwPAAzt2Gup\n" + //
      "IrxTbEUIaVq7iKQ5O2/MOjCcAwcyt8TurUHpZlAMBCUGbFFCzIqWfkMiwq/rFq42\n" + //
      "wdGAEApy1TFkbwzhAkjHdLoC6CF3dFkLgJrkB7193wvyaU1gEKtCE5nt1LR/hq3h\n" + //
      "quUtxqO3AgMBAAECggEBANX6C+7EA/TADrbcCT7fMuNnMb5iGovPuiDCWc6bUIZC\n" + //
      "Q0yac45l7o1nZWzfzpOkIprJFNZoSgIF7NJmQeYTPCjAHwsSVraDYnn3Y4d1D3tM\n" + //
      "5XjJcpX2bs1NactxMTLOWUl0JnkGwtbWp1Qq+DBnMw6ghc09lKTbHQvhxSKNL/0U\n" + //
      "C+YmCYT5ODmxzLBwkzN5RhxQZNqol/4LYVdji9bS7N/UITw5E6LGDOo/hZHWqJsE\n" + //
      "fgrJTPsuCyrYlwrNkgmV2KpRrGz5MpcRM7XHgnqVym+HyD/r9E7MEFdTLEaiiHcm\n" + //
      "Ish1usJDEJMFIWkF+rnEoJkQHbqiKlQBcoqSbCmoMWECgYEA/4379mMPF0JJ/EER\n" + //
      "4VH7/ZYxjdyphenx2VYCWY/uzT0KbCWQF8KXckuoFrHAIP3EuFn6JNoIbja0NbhI\n" + //
      "HGrU29BZkATG8h/xjFy/zPBauxTQmM+yS2T37XtMoXNZNS/ubz2lJXMOapQQiXVR\n" + //
      "l/tzzpyWaCe9j0NT7DAU0ZFmDbECgYEA6ZbjkcOs2jwHsOwwfamFm4VpUFxYtED7\n" + //
      "9vKzq5d7+Ii1kPKHj5fDnYkZd+mNwNZ02O6OGxh40EDML+i6nOABPg/FmXeVCya9\n" + //
      "Vump2Yqr2fAK3xm6QY5KxAjWWq2kVqmdRmICSL2Z9rBzpXmD5o06y9viOwd2bhBo\n" + //
      "0wB02416GecCgYEA+S/ZoEa3UFazDeXlKXBn5r2tVEb2hj24NdRINkzC7h23K/z0\n" + //
      "pDZ6tlhPbtGkJodMavZRk92GmvF8h2VJ62vAYxamPmhqFW5Qei12WL+FuSZywI7F\n" + //
      "q/6oQkkYT9XKBrLWLGJPxlSKmiIGfgKHrUrjgXPutWEK1ccw7f10T2UXvgECgYEA\n" + //
      "nXqLa58G7o4gBUgGnQFnwOSdjn7jkoppFCClvp4/BtxrxA+uEsGXMKLYV75OQd6T\n" + //
      "IhkaFuxVrtiwj/APt2lRjRym9ALpqX3xkiGvz6ismR46xhQbPM0IXMc0dCeyrnZl\n" + //
      "QKkcrxucK/Lj1IBqy0kVhZB1IaSzVBqeAPrCza3AzqsCgYEAvSiEjDvGLIlqoSvK\n" + //
      "MHEVe8PBGOZYLcAdq4YiOIBgddoYyRsq5bzHtTQFgYQVK99Cnxo+PQAvzGb+dpjN\n" + //
      "/LIEAS2LuuWHGtOrZlwef8ZpCQgrtmp/phXfVi6llcZx4mMm7zYmGhh2AsA9yEQc\n" + //
      "acgc4kgDThAjD7VlXad9UHpNMO8=\n" + //
      "-----END PRIVATE KEY-----";

  private final Map<String, String> users = new HashMap<>() {
    {
      this.put("serviceA", "69605c3eba8141ffa85ec07fa5d37886");
      this.put("serviceB", "0ec0448ee4ea49248ddd51e85376df64");
    }
  };

  @Autowired
  private JwtService jwtService;

  @GetMapping("/publickey")
  @ResponseBody
  public String getPublicKey() {
    return publicKey;
  }

  @PostMapping("/login")
  @ResponseBody
  public String login(@RequestBody Map<String, Object> body)
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    String username = (String) body.get("username");
    String inputPassword = (String) body.get("password");

    String password = users.get(username);
    if (!inputPassword.equals(password)) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Unauthorized");
    }

    long now = new Date().getTime() / 1000;
    long inOneMinute = (System.currentTimeMillis() + (1 * 60 * 1000)) / 1000;

    Map<String, Object> claims = new HashMap<>();
    claims.put("iss", "https://sts.windows.net/439dd1b8-73b6-4ae0-903d-521f615914b3/");
    claims.put("iat", now);
    claims.put("exp", inOneMinute);
    claims.put("jti", UUID.randomUUID().toString());
    claims.put("sub", username);
    claims.put("aud", "https://graph.microsoft.com");
    claims.put("nbf", now);

    claims.put("app_id", UUID.randomUUID().toString());
    claims.put("app_displayname", "SMBDomainServices_UAT_9908");
    claims.put("principal", username);
    claims.put("roles", Arrays.asList("User.Read.All"));

    String token = jwtService.createToken(claims, privateKey);
    log.info(username + " authenticated");
    return token;
  }

  @GetMapping("/signin")
  @ResponseBody
  public String signin(HttpServletRequest request) {
    log.info("signin");
    return "hello";
  }
}
