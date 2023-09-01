package com.example.demo.controllers;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.ThreadLocalRandom;
import java.util.logging.Logger;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Controller;
import com.google.gson.Gson;

@Controller
public class ServiceAController {
  private static final Logger log = Logger.getLogger(ServiceAController.class.getName());

  @Scheduled(fixedRate = 5000)
  public void makeRequest() throws ClientProtocolException, IOException {

    String token = login();

    List<String> list = new ArrayList<>(ServiceBController.records.keySet());
    int randomNum = ThreadLocalRandom.current().nextInt(0, list.size());
    String who = list.get(randomNum);
    log.info("Request record for: " + who);

    HttpGet get = new HttpGet("http://localhost:8080/records?who=" + who);
    get.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token);
    get.addHeader("Accept", String.valueOf(ContentType.APPLICATION_JSON));
    String response = send(get);
    log.info("Received record for: ");
    log.info("  " + response);
  }

  private String login() throws IOException, ClientProtocolException {
    Map<String, Object> body = new HashMap<>();
    body.put("username", "serviceA");
    body.put("password", "69605c3eba8141ffa85ec07fa5d37886");

    log.info("Requesting authentication");
    String token = getToken(body);
    return token;
  }

  private String getToken(Map<String, Object> body) throws IOException, ClientProtocolException {
    HttpPost request = new HttpPost("http://localhost:8080/login");
    request.addHeader("Accept", String.valueOf(ContentType.APPLICATION_JSON));
    String JSON_STRING = new Gson().toJson(body);
    HttpEntity stringEntity = new StringEntity(JSON_STRING, ContentType.APPLICATION_JSON);
    request.setEntity(stringEntity);

    String token = send(request);
    return token;
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
