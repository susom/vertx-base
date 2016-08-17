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

import com.github.susom.database.Config;
import com.github.susom.database.Metric;
import io.netty.handler.codec.http.QueryStringEncoder;
import io.netty.handler.codec.http.cookie.Cookie;
import io.netty.handler.codec.http.cookie.ServerCookieDecoder;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTOptions;
import io.vertx.ext.auth.jwt.impl.JWT;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.CookieHandler;
import io.vertx.ext.web.impl.CookieImpl;
import java.security.SecureRandom;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import static com.github.susom.vertx.base.VertxBase.mdc;
import static io.vertx.core.http.HttpHeaders.COOKIE;
import static io.vertx.core.http.HttpHeaders.SET_COOKIE;

/**
 * Provide standard security services for protecting applications.
 *
 * @author garricko
 */
public class SecurityImpl implements Security {
  private static final Logger log = LoggerFactory.getLogger(SecurityImpl.class);
  private static final Pattern VALID_AUTH_CODE = Pattern.compile("[\\.a-zA-Z0-9_/-]*");
  private final CookieHandler cookieHandler;
  private final Handler<RoutingContext> authenticateOptional;
  private final Handler<RoutingContext> authenticateRequiredOrDeny;
  private final Handler<RoutingContext> authenticateRequiredOrRedirect302;
  private final Handler<RoutingContext> authenticateRequiredOrRedirectJs;
  private final SecureRandom secureRandom;
  private final JWTAuth jwt;
  private final Config config;
  private HttpClient httpClient;
  private String authUrl;
  private String tokenUrl;
  private String logoutUrl;
  private String clientId;
  private String clientSecret;
  private String baseUri;
  private String redirectUri;
  private String scope;

  public SecurityImpl(Vertx vertx, SecureRandom secureRandom, JWTAuth jwt, Function<String, String> cfg) {
    this.secureRandom = secureRandom;
    this.jwt = jwt;
    config = Config.from().custom(cfg::apply).get();
    String authBaseUri = config.getString("auth.server.base.uri", "http://localhost:8080/auth/realms/demo/protocol/openid-connect");
    authUrl = config.getString("auth.server.login.uri", authBaseUri + "/auth");
    tokenUrl = config.getString("auth.server.token.uri", authBaseUri + "/token");
    logoutUrl = config.getString("auth.server.logout.uri", authBaseUri + "/logout");
    clientId = config.getStringOrThrow("auth.client.id");
    clientSecret = config.getString("auth.client.secret");
    baseUri = config.getString("auth.client.base.uri", "http://localhost:8000/secure-app");
    redirectUri = config.getString("auth.client.redirect.uri", baseUri + "/callback");
    scope = config.getString("auth.client.scope", "openid");

    if (httpClient == null) {
      httpClient = vertx.createHttpClient(
          new HttpClientOptions().setSsl(authBaseUri.startsWith("https")).setConnectTimeout(10000)
      );
    }

    cookieHandler = rc -> {
      // This is meant to be called from within on of our other handlers,
      // so we do not call rc.next() like the default CookieHandler, and
      // we try to protect against multiple calls
      if (rc.cookieCount() == 0 && rc.get("didCookieHandler") == null) {
        String cookieHeader = rc.request().headers().get(COOKIE);

        if (cookieHeader != null) {
          Set<Cookie> nettyCookies = ServerCookieDecoder.STRICT.decode(cookieHeader);
          for (Cookie cookie : nettyCookies) {
            io.vertx.ext.web.Cookie ourCookie = new CookieImpl(cookie);
            rc.addCookie(ourCookie);
          }
        }

        rc.addHeadersEndHandler(v -> {
          // save the cookies
          Set<io.vertx.ext.web.Cookie> cookies = rc.cookies();
          for (io.vertx.ext.web.Cookie cookie : cookies) {
            if (cookie.isChanged()) {
              rc.response().headers().add(SET_COOKIE, cookie.encode());
            }
          }
        });

        rc.put("didCookieHandler", "yes");
      }
    };
    Handler<RoutingContext> optional = WebAppJwtAuthHandler.optional(jwt);
    authenticateOptional = rc -> {
      if (rc.user() == null && rc.get("didAuthenticateOptional") == null) {
        rc.put("didAuthenticateOptional", "yes");

        cookieHandler.handle(rc);

        // This will call rc.next()
        optional.handle(rc);
      } else {
        rc.next();
      }
    };
    Handler<RoutingContext> mandatory = WebAppJwtAuthHandler.mandatory(jwt, rc -> {
      QueryStringEncoder params = new QueryStringEncoder("");

      params.addParam("client_id", clientId);
      params.addParam("response_type", "code");
      params.addParam("scope", scope);
      params.addParam("redirect_uri", redirectUri);
      String state = new TokenGenerator(secureRandom).create(15);
      params.addParam("state", state);

      rc.response().headers().add(SET_COOKIE, io.vertx.ext.web.Cookie.cookie("state", state)
          .setHttpOnly(true)
          .setPath(rc.mountPoint() + "/")
          .setSecure(redirectUri.startsWith("https")).encode());

      rc.response().setStatusCode(401).putHeader("WWW-Authenticate", "Redirect " + authUrl + params).end();
    });
    authenticateRequiredOrDeny = rc -> {
      if (rc.user() == null) {
        cookieHandler.handle(rc);

        // This will call rc.next()
        mandatory.handle(rc);
      } else {
        rc.next();
      }
    };
    Handler<RoutingContext> mandatoryRedirect = WebAppJwtAuthHandler.mandatory(jwt, rc -> {
      QueryStringEncoder params = new QueryStringEncoder("");

      params.addParam("client_id", clientId);
      params.addParam("response_type", "code");
      params.addParam("scope", scope);
      params.addParam("redirect_uri", redirectUri);
      String state = new TokenGenerator(secureRandom).create(15);
      params.addParam("state", state);

      rc.response().headers().add(SET_COOKIE, io.vertx.ext.web.Cookie.cookie("state", state)
          .setHttpOnly(true)
          .setPath(rc.mountPoint() + "/")
          .setSecure(redirectUri.startsWith("https")).encode());

      rc.response().setStatusCode(302).putHeader("location", authUrl + params).end();
    });
    authenticateRequiredOrRedirect302 = rc -> {
      if (rc.user() == null) {
        cookieHandler.handle(rc);

        // This will call rc.next()
        mandatoryRedirect.handle(rc);
      } else {
        rc.next();
      }
    };
    Handler<RoutingContext> mandatoryRedirectJs = WebAppJwtAuthHandler.mandatory(jwt, rc -> {
      QueryStringEncoder params = new QueryStringEncoder("");

      params.addParam("client_id", clientId);
      params.addParam("response_type", "code");
      params.addParam("scope", scope);
      params.addParam("redirect_uri", redirectUri);
      String state = new TokenGenerator(secureRandom).create(15);
      params.addParam("state", state);

      rc.response().headers().add(SET_COOKIE, io.vertx.ext.web.Cookie.cookie("state", state)
          .setHttpOnly(true)
          .setPath(rc.mountPoint() + "/")
          .setSecure(redirectUri.startsWith("https")).encode());

      rc.response().putHeader("content-type", "text/html").end("<!DOCTYPE html><html><body>"
          + "<noscript>\n"
          + "  <div style=\"width: 22em; position: absolute; left: 50%; margin-left: -11em; color: red; background-color: white; border: 1px solid red; padding: 4px; font-family: sans-serif\">\n"
          + "    Your web browser must have JavaScript enabled\n"
          + "    in order for this application to display correctly.\n"
          + "  </div>\n"
          + "</noscript>"
          + "<script type=\"application/javascript\">\n"
          + "var match = window.name.match(/windowId:([^;]+).*/);\n"
          + "if(match){window.name=\"windowId:\"+match[1]+\";q=\"+window.location.search+window.location.hash}\n"
          + "else{window.name=\"windowId:\"+Math.floor(Math.random()*1e16).toString(36).slice(0, 8)"
          + "+\";q=\"+window.location.search+window.location.hash}\n"
          + "window.location.href='" + authUrl + params + "';\n"
          + "</script></body></html>");
    });
    authenticateRequiredOrRedirectJs = rc -> {
      if (rc.user() == null) {
        cookieHandler.handle(rc);

        // This will call rc.next()
        mandatoryRedirectJs.handle(rc);
      } else {
        rc.next();
      }
    };
  }

//  @Override
//  public void registerApp(String appName) {
//    // TODO implement this by authenticating to the security coordinator
//    //   specify business and technical owners
//    //   specify supported static and dynamic permissions
//    //   read versions of Java and various libraries in classpath
//    //   determine environment instance (maybe some function of database host/schema/etc.?)
//  }

  @Override
  public Handler<RoutingContext> authenticateOptional() {
    return authenticateOptional;
  }

  @Override
  public Handler<RoutingContext> authenticateOrDeny() {
    return authenticateRequiredOrDeny;
  }

  @Override
  public Handler<RoutingContext> authenticateOrRedirect302() {
    return authenticateRequiredOrRedirect302;
  }

  @Override
  public Handler<RoutingContext> authenticateOrRedirectJs() {
    return authenticateRequiredOrRedirectJs;
  }

  @Override
  public Handler<RoutingContext> callbackHandler() {
    return rc -> {
      // XSRF prevention: Verify the state value provided to login call
      io.vertx.ext.web.Cookie state = rc.getCookie("state");
      if (state != null) {
        String stateParam = rc.request().getParam("state");
        if (stateParam == null || stateParam.length() == 0) {
          log.debug("Missing state parameter in login callback");
          rc.response().setStatusCode(403).end("Missing state parameter");
          return;
        } else if (!state.getValue().equals(stateParam)) {
//          log.debug("State from parameter does not match cookie (XSRF?)");
          log.warn("State from parameter does not match cookie (XSRF?) " + stateParam + " vs. " + state.getValue()); // TODO remove
          rc.response().setStatusCode(403).end("The state parameter does not match the cookie");
          return;
        }
      } else {
        log.error("Something went wrong with login. Could not verify state against"
            + " cookie because the cookie was missing.");
        rc.response().setStatusCode(403).end("The state cookie is missing");
        return;
      }

      QueryStringEncoder enc = new QueryStringEncoder("");

      enc.addParam("grant_type", "authorization_code");
      enc.addParam("code", Valid.matchesReq(rc.request().getParam("code"), VALID_AUTH_CODE, "Invalid code"));
      enc.addParam("client_id", clientId);
      enc.addParam("client_secret", clientSecret);
      enc.addParam("redirect_uri", redirectUri);
      enc.addParam("scope", scope);

      Metric metric = new Metric(log.isDebugEnabled());
      httpClient.postAbs(tokenUrl, mdc(response -> {
        metric.checkpoint("response");
        response.bodyHandler(mdc(body -> {
          try {
            metric.checkpoint("body", body.length());
            if (response.statusCode() == 200) {
              JsonObject json = new JsonObject(body.toString());

              String publicKey = config.getStringOrThrow("auth.server.public.key");
              JWT decoder = new JWT(publicKey);
              JsonObject id = decoder.decode(json.getString("id_token"));

              // TODO need to verify issuer, audience, etc. per spec
              log.warn("Response from token end point: " + json.encodePrettily()); // TODO remove
              JsonObject access = decoder.decode(json.getString("access_token"));
              log.warn("id_token: " + id.encodePrettily() + "\naccess_token: " + access.encodePrettily()); // TODO remove

              String sessionToken = jwt.generateToken(new JsonObject()
                      .put("sub", id.getString("preferred_username"))
                      .put("name", id.getString("name", id.getString("preferred_username"))),
                  new JWTOptions().setExpiresInSeconds(60 * 60 * 24L));

              io.vertx.ext.web.Cookie jwtCookie = io.vertx.ext.web.Cookie.cookie("access_token",
                  sessionToken).setHttpOnly(true)
                  .setSecure(redirectUri.startsWith("https"));
              io.vertx.ext.web.Cookie xsrfCookie = io.vertx.ext.web.Cookie.cookie("XSRF-TOKEN",
                  new TokenGenerator(secureRandom).create())
                  .setSecure(redirectUri.startsWith("https"));

              rc.response().headers()
                  .add(SET_COOKIE, jwtCookie.encode())
                  .add(SET_COOKIE, xsrfCookie.encode());
              rc.response().setStatusCode(302).putHeader("location", baseUri + "/").end();
            } else {
              log.error("Unexpected response connecting to " + tokenUrl + ": " + response.statusCode() + " "
                  + response.statusMessage() + " body: " + body);
              rc.response().setStatusCode(500).end("Bad response from token endpoint");
            }
          } catch (Exception e) {
            log.error("Unexpected error connecting to " + tokenUrl + ": " + response.statusCode() + " "
                + response.statusMessage() + " body: " + body);
            rc.response().setStatusCode(500).end("Bad response from token endpoint");
          } finally {
            log.debug("Request token: {}", metric.getMessage());
          }
        }));
      })).exceptionHandler(mdc(e -> {
        try {
          log.error("Unexpected error connecting to " + logoutUrl, e);
          rc.response().setStatusCode(500).end("Bad response from token endpoint");
        } finally {
          log.debug("Request token: {}", metric.getMessage());
        }
      })).putHeader("content-type", "application/x-www-form-urlencoded")
          .putHeader("X-REQUEST-ID", MDC.get("requestId"))
          .end(enc.toString().substring(1));
    };
  }

  @Override
  public Handler<RoutingContext> loginStatusHandler() {
    return rc -> {
      User user = rc.user();
      if (user != null) {
        JsonObject principal = user.principal();
        rc.response().end(new JsonObject()
            .put("authenticated", true)
            // TODO issuer; authenticated and acting principal; authority sets
            .put("accountId", principal.getString("sub"))
            .put("userDisplayName", principal.getString("name")).encode());
      } else {
        QueryStringEncoder params = new QueryStringEncoder("");

        params.addParam("client_id", clientId);
        params.addParam("response_type", "code");
        params.addParam("scope", scope);
        params.addParam("redirect_uri", redirectUri);
        String state = new TokenGenerator(secureRandom).create(15);
        params.addParam("state", state);

        rc.response().headers().add(SET_COOKIE, io.vertx.ext.web.Cookie.cookie("state", state)
            .setHttpOnly(true)
            .setSecure(redirectUri.startsWith("https")).encode());

        rc.response().end(new JsonObject()
            .put("authenticated", false)
            .put("loginUrl", authUrl + params).encode());
      }
    };
  }

  @Override
  public Handler<RoutingContext> logoutHandler() {
    return rc -> {
      if ("yes".equals(rc.request().getParam("done"))) {
        rc.response().end("Logout complete");
        return;
      }

      QueryStringEncoder fromEnc = new QueryStringEncoder("");
      fromEnc.addParam("redirect_uri", VertxBase.absolutePath(config::getString, rc) + "?done=yes");

      rc.response().headers()
          .add(SET_COOKIE, io.vertx.ext.web.Cookie.cookie("access_token", "").setMaxAge(0).encode())
          .add(SET_COOKIE, io.vertx.ext.web.Cookie.cookie("XSRF-TOKEN", "").setMaxAge(0).encode())
          .add("location", logoutUrl + fromEnc);
      rc.response().setStatusCode(302).end();
    };
  }
}
