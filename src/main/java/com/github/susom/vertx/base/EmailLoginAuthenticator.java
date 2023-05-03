/*
 * Copyright 2023 The Board of Trustees of The Leland Stanford Junior University.
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
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import org.owasp.encoder.Encode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import static com.github.susom.vertx.base.VertxBase.absoluteContext;
import static com.github.susom.vertx.base.VertxBase.absoluteRoot;
import static io.vertx.core.http.HttpHeaders.SET_COOKIE;
import static java.nio.charset.StandardCharsets.UTF_8;

public class EmailLoginAuthenticator implements Security {
  private static final Logger log = LoggerFactory.getLogger(EmailLoginAuthenticator.class);
  private final Vertx vertx;
  private final Router root;
  private final SecureRandom secureRandom;
  private final EmailLoginValidator validator;
  private final Config config;
  private final JWTAuth jwt;
  private final String loginpageTemplate;

  public EmailLoginAuthenticator(Vertx vertx, Router root, SecureRandom random, EmailLoginValidator validator, Function<String, String> cfg) throws IOException {
    this.vertx = vertx;
    this.root = root;
    this.secureRandom = random;
    this.validator = validator;
    this.config = Config.from().custom(cfg).get();

    String footer = config.getString("email.message.footer");
    footer = footer == null ? "" : footer;
    String resource = config.getString("email.template.resource", "/static/email-authentication/email.nocache.html");
    try (Reader reader = new InputStreamReader(Objects.requireNonNull(
        getClass().getResourceAsStream(resource), "Could not load from classpath: " + resource), UTF_8)) {
      StringBuilder builder = new StringBuilder();
      char[] buffer = new char[8192];
      int read;
      while ((read = reader.read(buffer, 0, buffer.length)) > 0) {
        builder.append(buffer, 0, read);
      }
      loginpageTemplate = builder.toString()
          .replaceAll("HEADER_MESSAGE", Encode.forHtml(config.getString("email.message.header", "Enter your email address to access this site.")))
          .replaceAll("LABEL_MESSAGE", Encode.forHtml(config.getString("email.message.label", "Email address:")))
          .replaceAll("PLACEHOLDER_MESSAGE", Encode.forHtml(config.getString("email.message.placeholder", "you@example.com")))
          .replaceAll("BUTTON_MESSAGE", Encode.forHtml(config.getString("email.message.button", "Send me an Email Link")))
          .replaceAll("INSTRUCTIONS", Encode.forHtml(config.getString("email.message.instructions", "An email will be sent if you entered an allowed email address.")))
          .replaceAll("FOOTER_MESSAGE", Encode.forHtml(footer));
    }

    jwt = JWTAuth.create(vertx, new JWTAuthOptions()
        .addPubSecKey(new PubSecKeyOptions()
            .setAlgorithm("HS256")
            .setPublicKey(config.getStringOrThrow("email.jwt.secret"))
            .setSymmetric(true)));
  }

  @Override
  public Router authenticatedRouter(String mountPoint) {
    Router router = Router.router(vertx);
    StrictBodyHandler smallBodyHandler = new StrictBodyHandler(4000);

    // Optional authenticate just to populate user information into the logs
    router.route().handler(checkAuthentication(false));
    router.route().handler(new MetricsHandler(secureRandom, config.getBooleanOrFalse("insecure.log.full.requests")));
    router.get("/*").handler(new StrictResourceHandler(vertx).addDir("static/assets-public", "**/*", "assets"));

    router.get("/t/:token/*").handler(rc -> {
      validator.authenticate(rc.pathParam("token"))
          .onSuccess(user -> {
            // Figure out what the wildcard represents in the router above
            String prefix = rc.mountPoint() + "/t/" + rc.pathParam("token") + "/";
            String wildcard;
            if (rc.request().path().startsWith(prefix)) {
              wildcard = rc.request().path().substring(prefix.length());
              if (rc.request().query() != null && rc.request().query().length() > 0) {
                wildcard += "?" + rc.request().query();
              }
            } else {
              wildcard = rc.mountPoint();
            }

            if (user == null) {
              String newPath = rc.mountPoint() + "auth/" + wildcard;
              log.debug("Token invalid - redirecting to login screen: {}", newPath);
              rc.response().setStatusCode(302).putHeader("Location", absoluteRoot(config::getString) + newPath).end();
            } else {
              String token = jwt.generateToken(
                  user.principal(),
                  new JWTOptions()
                      .setAlgorithm("HS256")
                      .setExpiresInMinutes(config.getInteger("email.sesssion.timeout.minutes", 60)));
              String tokenBase64 = Base64.getEncoder().encodeToString(token.getBytes(UTF_8));

              rc.response().headers().add(SET_COOKIE, Cookie.cookie("session_token", tokenBase64)
                  .setHttpOnly(true)
                  .setPath(rc.mountPoint() + "/")
                  .setSecure(absoluteContext(config::getString, rc).startsWith("https")).encode());
              log.debug("Token valid - redirecting to destination: {}", wildcard);
              rc.response().setStatusCode(302).putHeader("Location", absoluteRoot(config::getString) + wildcard).end();
            }
          })
          .onFailure(throwable -> {
            String loginpage = loginpageTemplate.replaceAll("BASE_PATH", rc.mountPoint());
            rc.response().putHeader("content-type", "text/html").end(loginpage);
          });
    }).failureHandler(VertxBase::jsonApiFail);

    router.get("/auth/*").handler(rc -> {
      String loginpage = loginpageTemplate.replaceAll("BASE_PATH", rc.mountPoint());
      rc.response().putHeader("content-type", "text/html").end(loginpage);
    }).failureHandler(VertxBase::jsonApiFail);

    // Static login page sends us the username here
    router.post("/mail").handler(smallBodyHandler);
    router.post("/mail").handler(this::sendEmail).failureHandler(VertxBase::jsonApiFail);

    router.get("/logout").handler(logoutHandler()).failureHandler(VertxBase::jsonApiFail);

    // Mandatory authenticate
    router.route().handler(checkAuthentication(true)).failureHandler(VertxBase::jsonApiFail);

    // Now layer in any assets that should be behind authentication (keep in mind
    // things like source maps will not work for resources here because the browser
    // does not pass session cookies or special headers)
    router.get("/assets/*").handler(new StrictResourceHandler(vertx).addDir("static/assets-private", "**/*", "assets"));

    // Information for the client about whether we are logged in, how to login, etc.
    router.get("/login-status").handler(loginStatusHandler()).failureHandler(VertxBase::jsonApiFail);

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

  private Handler<RoutingContext> checkAuthentication(boolean isMandatory) {
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
          } else {
            rc.next();
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
          .putHeader("WWW-Authenticate", "Redirect " + loginUrl + "/{request}")
          .end("401 Authentication Required");
    } else if ("document".equals(rc.request().getHeader("Sec-Fetch-Dest"))) {
      rc.response().putHeader("content-type", "text/html").end("<html><body>\n"
          + "<noscript>\n"
          + "  <div style=\"width: 22em; position: absolute; left: 50%; margin-left: -11em; color: red; background-color: white; border: 1px solid red; padding: 4px; font-family: sans-serif\">\n"
          + "    Your web browser must have JavaScript enabled\n"
          + "    in order for this application to display correctly.\n"
          + "  </div>\n"
          + "</noscript>\n"
          + "<script type=\"application/javascript\">\n"
          + "  window.location.href='" + Encode.forJavaScript(loginUrl) + "' + window.location.pathname + window.location.search + window.location.hash;\n"
          + "</script></body></html>\n");
    } else {
      rc.response().setStatusCode(302).putHeader("Location", loginUrl + rc.request().path() + "?" + rc.request().query()).end();
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
          .add("location", VertxBase.absolutePath(config::getString, rc) + "?done=yes");
      rc.response().setStatusCode(302).end();
    };
  }

  private void sendEmail(RoutingContext rc) {
    JsonObject loginJson = Valid.nonNull(rc.getBodyAsJson(), "No body");
    String loginDestPath = loginJson.getString("destpath", rc.mountPoint());
    String loginUrl = rc.mountPoint() + "/auth";
    if (loginDestPath.startsWith(loginUrl)) {
      loginDestPath = loginDestPath.substring(loginUrl.length());
    }
    String finalLoginDestPath = loginDestPath;

    String email = loginJson.getString("email");
    validator.generateEmailToken(email)
        .onSuccess(token -> {
          // TODO implement this
          log.warn("Here is your email:\nTo: {}\nLink: {}/t/{}/app?a=b#c", email, absoluteContext(config::getString, rc), token);
          rc.response().setStatusCode(200).end();
        })
        .onFailure(throwable -> {
          log.error("Error creating email token for the user", throwable);
          rc.response().headers()
              .add(SET_COOKIE, Cookie.cookie("session_token", "").setMaxAge(0).encode());
          rc.response().setStatusCode(401)
              .putHeader("content-type", "application/json")
              .end(new JsonObject().put("message", "Unable to check the password.").encode());
        });
  }
}
