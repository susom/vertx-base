/*
 * Copyright 2022 The Board of Trustees of The Leland Stanford Junior University.
 * All Rights Reserved.
 *
 * See the NOTICE and LICENSE files distributed with this work for information
 * regarding copyright ownership and licensing. You may not use this file except
 * in compliance with a written license agreement with Stanford University.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See your
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package com.github.susom.vertx.base;

import com.github.susom.database.Config;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.http.Cookie;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;
import org.owasp.encoder.Encode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import static com.github.susom.vertx.base.VertxBase.absoluteContext;
import static io.vertx.core.http.HttpHeaders.SET_COOKIE;

public class PasswordOnlyAuthenticator implements Security {
  private static final Logger log = LoggerFactory.getLogger(PasswordOnlyAuthenticator.class);
  private final Vertx vertx;
  private final Router root;
  private final SecureRandom secureRandom;
  private final PasswordOnlyValidator validator;
  private final Config config;
  private final JWTAuth jwt;

  public PasswordOnlyAuthenticator(Vertx vertx, Router root, SecureRandom random, PasswordOnlyValidator validator, Function<String, String> cfg) {
    this.vertx = vertx;
    this.root = root;
    this.secureRandom = random;
    this.validator = validator;
    this.config = Config.from().custom(cfg).get();

    jwt = JWTAuth.create(vertx, new JWTAuthOptions()
        .addPubSecKey(new PubSecKeyOptions()
            .setAlgorithm("HS256")
            .setPublicKey(config.getString("jwt.secret"))
            .setSymmetric(true)));
  }

  @Override
  public Router authenticatedRouter(String mountPoint) {
    Router router = Router.router(vertx);
    StrictBodyHandler smallBodyHandler = new StrictBodyHandler(4000);

    // Optional authenticate just to populate user information into the logs
    router.route().handler(authenticate(false));
    router.route().handler(new MetricsHandler(secureRandom, config.getBooleanOrFalse("insecure.log.full.requests")));
    router.get("/*").handler(new StrictResourceHandler(vertx)
            .addDir("static/assets-public", "**/*", "assets")
            .addDir("static/password-only-authentication")
            .rename("password-only.nocache.html", "auth"));

    // Static login page sends us the username here
    router.post("/authenticate").handler(smallBodyHandler);
    router.post("/authenticate").handler(this::authenticate).failureHandler(VertxBase::jsonApiFail);

    router.get("/logout").handler(logoutHandler());

    // Mandatory authenticate
    router.route().handler(authenticate(true));

    // Now layer in any assets that should be behind authentication (keep in mind
    // things like source maps will not work for resources here because the browser
    // does not pass session cookies or special headers)
    router.get("/assets/*").handler(new StrictResourceHandler(vertx).addDir("static/assets-private", "**/*", "assets"));

    // Information for the client about whether we are logged in, how to login, etc.
    router.get("/login-status").handler(loginStatusHandler());

    root.mountSubRouter(mountPoint, router);
    return router;
  }

  @Override
  public Handler<RoutingContext> requireAuthority(String authority) {
    return rc -> {
      AuthenticatedUser user = AuthenticatedUser.from(rc);
      if (user == null) {
        log.warn("No authenticated user");
        rc.response().setStatusCode(401).end("401 Authentication Required");
      } else {
        user.isAuthorized(authority, r -> {
          if (r.succeeded() && r.result()) {
            rc.next();
          } else {
            log.warn("RequiredAuthorityMissing=\"" + authority + "\" User=" + user.principal().encode());
            rc.response().setStatusCode(403).end("403 Insufficient Authority");
          }
        });
      }
    };
  }

  private Handler<RoutingContext> authenticate(boolean isMandatory) {
    return rc -> {
      AuthenticatedUser user = AuthenticatedUser.from(rc);
      if (user != null) {
        String userId = user.getAuthenticatedAs();
        if (!userId.equals(MDC.get("userId"))) {
          log.warn("User from routing context (" + userId + ") did not match logging context ("
              + MDC.get("userId") + ")");
          MDC.put("userId", userId);
        }
        rc.next();
      } else {
        MDC.remove("userId");

        String windowId = rc.request().getHeader("X-WINDOW-ID");
        if (windowId != null && windowId.matches("[a-zA-Z0-9]{1,32}")) {
          MDC.put("windowId", windowId);
        } else {
          MDC.remove("windowId");
        }

        Cookie sessionCookie = rc.getCookie("session_token");

        if (sessionCookie != null) {
          String decoded = new String(Base64.getDecoder().decode(sessionCookie.getValue()));
          jwt.authenticate(new JsonObject().put("jwt", decoded), token -> {
            if (token.succeeded()) {
              MetricsHandler.checkpoint(rc, "auth");
              JsonObject principal = token.result().principal();
              JsonArray authorityArray = principal.getJsonArray("authority");
              Set<String> authority = new HashSet<>();
              for (int i = 0; i < authorityArray.size(); i++) {
                authority.add(authorityArray.getString(i));
              }
              AuthenticatedUser newUser = new AuthenticatedUser(principal.getString("sub"),
                  principal.getString("forsub"),
                  principal.getString("name"),
                  authority).store(rc);
              MDC.put("userId", newUser.getAuthenticatedAs());
              rc.next();
            } else {
              if (isMandatory) {
                MetricsHandler.checkpoint(rc, "authFail");
                log.trace("Token validation failed", token.cause());
                sendRedirectOrDeny(rc);
              } else {
                rc.next();
              }
            }
          });
        } else {
          if (isMandatory) {
            MetricsHandler.checkpoint(rc, "authNoCookie");
            sendRedirectOrDeny(rc);
          }
        }
      }
    };
  }

  private void sendRedirectOrDeny(RoutingContext rc) {
    rc.response().headers().add(SET_COOKIE, Cookie.cookie("session_token", "").setMaxAge(0).encode());

    String loginUrl = absoluteContext(config::getString, rc) + "/auth";
    if ("XMLHttpRequest".equals(rc.request().getHeader("X-Requested-With"))) {
      rc.response().setStatusCode(401)
          .putHeader("WWW-Authenticate", "Redirect " + loginUrl)
          .end("401 Authentication Required");
    } else if ("document".equals(rc.request().getHeader("Sec-Fetch-Dest"))) {
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
          + "window.location.href='" + Encode.forJavaScript(loginUrl) + "';\n"
          + "</script></body></html>");
    } else {
      rc.response().setStatusCode(302).putHeader("location", loginUrl).end();
    }
  }

  private Handler<RoutingContext> loginStatusHandler() {
    return rc -> {
      AuthenticatedUser user = AuthenticatedUser.from(rc);
      if (user != null) {
        rc.response().end(new JsonObject()
            .put("authenticated", true)
            .put("accountId", user.getAuthenticatedAs())
            .put("userDisplayName", user.getFullDisplayName()).encode());
      } else {
        String loginUrl = absoluteContext(config::getString, rc) + "/auth";
        rc.response().end(new JsonObject()
            .put("authenticated", false)
            .put("loginUrl", loginUrl).encode());
      }
    };
  }

  private Handler<RoutingContext> logoutHandler() {
    return rc -> {
      if ("yes".equals(rc.request().getParam("done"))) {
        rc.response().setStatusCode(302).putHeader("Location", absoluteContext(config::getString, rc)).end();
        return;
      }

      rc.response().headers()
          .add(SET_COOKIE, Cookie.cookie("session_token", "")
              .setMaxAge(0)
              .setHttpOnly(true)
              .setPath(rc.mountPoint() + "/")
              .setSecure(absoluteContext(config::getString, rc).startsWith("https")).encode())
          .add(SET_COOKIE, Cookie.cookie("XSRF-TOKEN", "")
              .setMaxAge(0)
              .setHttpOnly(true)
              .setPath(rc.mountPoint() + "/")
              .setSecure(absoluteContext(config::getString, rc).startsWith("https")).encode())
          .add("location", VertxBase.absolutePath(config::getString, rc) + "?done=yes");
      rc.response().setStatusCode(302).end();
    };
  }

  private void authenticate(RoutingContext rc) {
    JsonObject loginJson = Valid.nonNull(rc.getBodyAsJson(), "No body");
    AuthenticatedUser user = validator.authenticate(loginJson.getString("password"));

    if (user != null) {
      String token = jwt.generateToken(
          user.principal(),
          new JWTOptions()
              .setAlgorithm("HS256")
              .setExpiresInMinutes(1));
      String tokenBase64 = Base64.getEncoder().encodeToString(token.getBytes(StandardCharsets.UTF_8));

      rc.response().headers().add(SET_COOKIE, Cookie.cookie("session_token", tokenBase64)
          .setHttpOnly(true)
          .setPath(rc.mountPoint() + "/")
          .setSecure(absoluteContext(config::getString, rc).startsWith("https")).encode());
      rc.response().putHeader("content-type", "application/json").end(new JsonObject()
          .put("action", "redirect")
          .put("url", "/app/").encodePrettily() + '\n');
    } else {
      rc.response().headers()
          .add(SET_COOKIE, Cookie.cookie("session_token", "").setMaxAge(0).encode());
      rc.response().setStatusCode(401)
          .putHeader("content-type", "application/json")
          .end(new JsonObject().put("message", "Incorrect password.").encode());
    }
  }
}
