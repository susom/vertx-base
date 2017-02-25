/*
 * Copyright 2016 The Board of Trustees of The Leland Stanford Junior University.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.github.susom.vertx.base;

import io.netty.handler.codec.http.QueryStringEncoder;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * This is a completely fake version of a centralized (OpenID Connect)
 * authentication server. It is to be used only for development. Instead
 * of actually performing any authentication it simply asks who you would
 * like to be.
 *
 * @author garricko
 */
public class FakeAuthentication {
  private static final Pattern USER_PATTERN = Pattern.compile("[a-zA-Z0-9_\\.\\-]{1,40}@?[a-zA-Z0-9_\\.\\-]{0,40}");
  private static final Pattern NAME_PATTERN = Pattern.compile("[a-zA-Z0-9 '\\.\\-]{1,40}");
//  private static final Pattern AUTHORITY_PATTERN = Pattern.compile(".*");// TODO Pattern.compile("([a-zA-Z0-9]+([:\\-][a-zA-Z0-9+])*)([,]([a-zA-Z0-9]+([:\\-][a-zA-Z0-9+])*))*");
  private final SecureRandom secureRandom;
  private final String clientId;
  private final String clientSecret;
  private final String redirectUriPrefix;
  private final Set<String> staticAuthorities;
  private final Map<String, Auth> codeToAuth = new HashMap<>();

  public FakeAuthentication(SecureRandom secureRandom, String clientId, String clientSecret, String redirectUriPrefix, Set<String> staticAuthorities) {
    this.secureRandom = secureRandom;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.redirectUriPrefix = redirectUriPrefix;
    this.staticAuthorities = staticAuthorities;
  }

  public void configureRouter(Vertx vertx, Router router) {
    StrictBodyHandler smallBodyHandler = new StrictBodyHandler(4000);

    router.route().handler(new MetricsHandler(secureRandom));

    // Send a list of the static authorities we know about, so user can see them and pick from a list
    router.get("/authorities").handler(this::sendAuthorities).failureHandler(VertxBase::jsonApiFail);

    // Static login page sends us the username here
    router.post("/authenticate").handler(smallBodyHandler);
    router.post("/authenticate").handler(this::authenticate).failureHandler(VertxBase::jsonApiFail);

    // The application will use this to verify the login and obtain user info
    router.post("/token").handler(rc -> {
      // Make the HTML form encoded body accessible to getFormAttribute()
      rc.request().setExpectMultipart(true);
      rc.next();
    });
    router.post("/token").handler(smallBodyHandler);
    router.post("/token").handler(this::issueToken).failureHandler(VertxBase::jsonApiFail);

    // The application logout page will redirect here and we redirect back
    router.get("/logout").handler(this::logout).failureHandler(VertxBase::jsonApiFail);

    // Serve static html and related resources for the login/logout client
    router.get("/*").handler(new StrictResourceHandler(vertx)
        .addDir("static/fake-authentication")
        .addDir("static/assets-public", "**/*", "assets")
        .rename("login.nocache.html", "auth")
    );
  }

  private void sendAuthorities(RoutingContext rc) {
    rc.response().putHeader("content-type", "application/json").end(new JsonObject()
        .put("authorities", staticAuthorities.stream().sorted().collect(Collectors.toList())).encodePrettily() + '\n');
  }

  private void logout(RoutingContext rc) {
    String redirectUri = Valid.nonNullNormalized(rc.request().getParam("redirect_uri"), "Invalid redirect uri");
    if (!redirectUri.startsWith(redirectUriPrefix)) {
      throw new BadRequestException("Invalid redirect uri");
    }

    rc.response().setStatusCode(302).putHeader("Location", redirectUri).end();
  }

  private void authenticate(RoutingContext rc) {
    JsonObject loginJson = Valid.nonNull(rc.getBodyAsJson(), "No body");

    // Verify client id and redirect uri
    if (!Valid.safeReq(loginJson.getString("clientId"), "Invalid client").equals(clientId)) {
      throw new BadRequestException("Invalid client");
    }
    String redirectUri = Valid.nonNullNormalized(loginJson.getString("redirectUri"), "Invalid redirect uri");
    if (!redirectUri.startsWith(redirectUriPrefix)) {
      throw new BadRequestException("Invalid redirect uri");
    }
//    String redirectUri = Valid.matchesReq(loginJson.getString("redirectUri"), clientRedirectUri, "Invalid redirectUri");

    // The openid scope must be first or the only one (per standard)
    String scope = loginJson.getString("scope");
    if (scope == null || !(scope.equals("openid") || scope.startsWith("openid "))) {
      throw new BadRequestException("No scope or invalid scope");
    }

    // Generate a code and associate it with the "authenticated" user
    Auth auth = new Auth();
    auth.user = Valid.matchesReq(loginJson.getString("username"), USER_PATTERN, "Illegal username");
    auth.name = Valid.matchesOpt(loginJson.getString("displayname"), NAME_PATTERN, "Illegal displayname");
    auth.actuser = Valid.matchesOpt(loginJson.getString("actusername"), USER_PATTERN, "Illegal actusername");
    auth.actname = Valid.matchesOpt(loginJson.getString("actdisplayname"), NAME_PATTERN, "Illegal actdisplayname");
    auth.authority = new HashSet<>();
    String authorityStr = loginJson.getString("authority");//Valid.matchesOpt(loginJson.getString("authority"), AUTHORITY_PATTERN, "Illegal authority");
    if (authorityStr != null) {
      Collections.addAll(auth.authority, authorityStr.split("[,\\h\\s]"));
    }
    auth.scope = scope;
    String code = new TokenGenerator(secureRandom).create(32);
    codeToAuth.put(code, auth);

    QueryStringEncoder params = new QueryStringEncoder("");

    params.addParam("code", code);
    params.addParam("state", loginJson.getString("state"));

    rc.response().putHeader("content-type", "application/json").end(new JsonObject()
        .put("action", "redirect")
        .put("url", redirectUri + params).encodePrettily() + '\n');
  }

  private void issueToken(RoutingContext rc) {
    Valid.formAttributeEqualsShow(rc, "grant_type", "authorization_code");
    if (!Valid.safeFormAttributeReq(rc, "client_id").equals(clientId)) {
      throw new BadRequestException("Invalid client");
    }
    if (!Valid.safeFormAttributeReq(rc, "client_secret").equals(clientSecret)) {
      throw new BadRequestException("Invalid client");
    }

    String authCode = Valid.safeFormAttributeReq(rc, "code");
    Auth auth = Valid.nonNull(codeToAuth.get(authCode), "Authorization code not valid");

//      if (code == null || code.expires.isBefore(Instant.now())) {
//        throw new BadRequest("Code not valid or expired");
//      }
//
//      Valid.formAttributeEqualsHide(rc, "scope", code.scope);
//
//      Valid.formAttributeEqualsHide(rc, "redirect_uri", client.redirectUri);

    rc.response().putHeader("content-type", "application/json").end(new JsonObject()
        .put("sub", auth.user)
        .put("name", auth.name)
        .put("actsub", auth.actuser)
        .put("actname", auth.actname)
        .put("authority", new JsonArray(auth.authority.stream().collect(Collectors.toList())))
        .put("scope", auth.scope).encodePrettily() + '\n');
  }

  private static class Auth {
    String user;
    String name;
    String actuser;
    String actname;
    Set<String> authority;
    String scope;
//    Instant expires;
  }
}
