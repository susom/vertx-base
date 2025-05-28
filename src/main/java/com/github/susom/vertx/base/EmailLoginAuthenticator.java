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
import com.github.susom.database.Metric;
import io.netty.handler.codec.http.QueryStringEncoder;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.http.Cookie;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
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
  public final static String FOOTER_TEXT = "email.message.footer.text";
  public final static String FOOTER_HTML = "email.message.footer.html";

  public final static String HEADER_TEXT = "email.message.header.text";
  public final static String HEADER_HTML = "email.message.header.html";

  public final static String MAILGUN_API_KEY = "mailgun.api.key";
  public final static String MAILGUN_DOMAIN = "mailgun.domain";
  public final static String MAILGUN_FROM = "mailgun.from";
  public final static String MAILGUN_HOST = "mailgun.host";
  public final static String MAILGUN_HTML = "mailgun.html";
  public final static String MAILGUN_REPLY_TO = "mailgun.reply.to";
  public final static String MAILGUN_SUBJECT = "mailgun.subject";
  public final static String MAILGUN_TEXT = "mailgun.text";

  private static final Logger log = LoggerFactory.getLogger(EmailLoginAuthenticator.class);
  private final Vertx vertx;
  private final Router root;
  private final SecureRandom secureRandom;
  private final EmailLoginValidator validator;
  private final Config config;
  private final JWTAuth jwt;
  private final String loginPageTemplate;
  private final HttpClient httpClient;
  private final String mailgunHost;
  private final String mailgunDomain;
  private final String mailgunApiKey;
  private final String mailgunFrom;
  private final String mailgunReplyTo;

  public EmailLoginAuthenticator(Vertx vertx, Router root, SecureRandom random, EmailLoginValidator validator, Function<String, String> cfg) throws IOException {
    this.vertx = vertx;
    this.root = root;
    this.secureRandom = random;
    this.validator = validator;
    this.config = Config.from().custom(cfg).get();

    String footerText = config.getString(FOOTER_TEXT);
    footerText = footerText == null ? "" : footerText;
    String footerHtml = config.getString(FOOTER_HTML);
    footerHtml = footerHtml == null ? "" : footerHtml;
    String headerText = config.getString(HEADER_TEXT);
    headerText = headerText == null ? "" : headerText;
    String headerHtml = config.getString(HEADER_HTML);
    headerHtml = headerHtml == null ? "" : headerHtml;
    if (headerText.isEmpty() && headerHtml.isEmpty()) {
      headerText = "Enter your email address to access this site.";
    }
    String resource = config.getString("email.template.resource", "/static/email-authentication/email.nocache.html");
    try (Reader reader = new InputStreamReader(Objects.requireNonNull(
        getClass().getResourceAsStream(resource), "Could not load from classpath: " + resource), UTF_8)) {
      StringBuilder builder = new StringBuilder();
      char[] buffer = new char[8192];
      int read;
      while ((read = reader.read(buffer, 0, buffer.length)) > 0) {
        builder.append(buffer, 0, read);
      }
      loginPageTemplate = builder.toString()
          .replaceAll("HEADER_MESSAGE_TEXT", Encode.forHtml(headerText))
          .replaceAll("HEADER_MESSAGE_HTML", headerHtml)
          .replaceAll("LABEL_MESSAGE", Encode.forHtml(config.getString("email.message.label", "Email address:")))
          .replaceAll("PLACEHOLDER_MESSAGE", Encode.forHtml(config.getString("email.message.placeholder", "you@example.com")))
          .replaceAll("BUTTON_MESSAGE", Encode.forHtml(config.getString("email.message.button", "Send me an Email Link")))
          .replaceAll("INSTRUCTIONS", Encode.forHtml(config.getString("email.message.instructions", "An email will be sent if you entered an allowed email address.")))
          .replaceAll("FOOTER_MESSAGE_TEXT", Encode.forHtml(footerText))
          .replaceAll("FOOTER_MESSAGE_HTML", footerHtml);
    }

    jwt = JWTAuth.create(vertx, new JWTAuthOptions()
        .addPubSecKey(new PubSecKeyOptions()
            .setAlgorithm("HS256")
            .setPublicKey(config.getStringOrThrow("email.jwt.secret"))
            .setSymmetric(true)));

    httpClient = vertx.createHttpClient(new HttpClientOptions().setSsl(true));

    mailgunHost = config.getString(MAILGUN_HOST, "api.mailgun.net");
    mailgunDomain = config.getString(MAILGUN_DOMAIN);
    mailgunApiKey = config.getString(MAILGUN_API_KEY);
    mailgunFrom = config.getString(MAILGUN_FROM);
    mailgunReplyTo = config.getString(MAILGUN_REPLY_TO);

    if (mailgunDomain == null || mailgunApiKey == null || mailgunFrom == null) {
      log.warn("Config mailgun.domain, mailgun.api.key, or mailgun.from is not set so we will log emails instead of sending");
    }
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
                      .setExpiresInMinutes(config.getInteger("email.session.timeout.minutes", 60)));
              String tokenBase64 = Base64.getEncoder().encodeToString(token.getBytes(UTF_8));

              setSessionCookie(rc, tokenBase64);
              log.debug("Token valid - redirecting to destination: {}", wildcard);
              rc.response().setStatusCode(302).putHeader("Location", absoluteRoot(config::getString) + wildcard).end();
            }
          })
          .onFailure(throwable -> {
            String loginpage = loginPageTemplate.replaceAll("BASE_PATH", rc.mountPoint());
            rc.response().putHeader("content-type", "text/html").end(loginpage);
          });
    }).failureHandler(VertxBase::jsonApiFail);

    router.get("/auth/*").handler(rc -> {
      String loginpage = loginPageTemplate.replaceAll("BASE_PATH", rc.mountPoint());
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

        Cookie sessionCookie = rc.getCookie("email_session");
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
    removeSessionCookie(rc);

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

      removeSessionCookie(rc);
      rc.response().headers().add("Location", VertxBase.absolutePath(config::getString, rc) + "?done=yes");
      rc.response().setStatusCode(302).end();
    };
  }

  private void sendEmail(RoutingContext rc) {
    JsonObject loginJson = Valid.nonNull(rc.getBodyAsJson(), "No body");
    String loginDestPath = loginJson.getString("destpath", rc.mountPoint());
    String loginUrl = rc.mountPoint() + "/auth/";
    if (loginDestPath.startsWith(loginUrl)) {
      loginDestPath = loginDestPath.substring(loginUrl.length());
    }
    String finalLoginDestPath = loginDestPath;

    String email = loginJson.getString("email");
    validator.generateEmailToken(email)
        .onSuccess(token -> {
          String link = absoluteContext(config::getString, rc) + "/t/" + token + "/" + finalLoginDestPath;

          if (mailgunDomain == null || mailgunApiKey == null || mailgunFrom == null) {
            log.warn("Here is your email:\nTo: {}\nLink: {}", email, link);
            rc.response().setStatusCode(200).end();
            return;
          }

          Metric metric = new Metric(log.isDebugEnabled());
          QueryStringEncoder enc = new QueryStringEncoder("");
          enc.addParam("from", mailgunFrom);
          enc.addParam("to", email);
          if (mailgunReplyTo != null) {
            enc.addParam("h:Reply-To", mailgunReplyTo);
          }
          enc.addParam("subject", config.getString(MAILGUN_SUBJECT, "The login link you requested"));
          String text = config.getString(MAILGUN_TEXT);
          String html = config.getString(MAILGUN_HTML);
          if (text == null && html == null) {
            text = "Here is the login link you requested:\n\n[LINK]\n\nDo not forward or share with anyone.";
          }
          if (text != null) {
            enc.addParam("text", text.replace("[LINK]", link));
          }
          if (html != null) {
            enc.addParam("html", html.replace("[LINK]", link));
          }
          String encodedBody = enc.toString().substring(1);
          httpClient.post(443, mailgunHost, "/v3/" + mailgunDomain + "/messages")
              .putHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString(("api:" + mailgunApiKey).getBytes(UTF_8)))
              .putHeader("content-type", "application/x-www-form-urlencoded")
              .handler(response -> {
                try {
                  metric.checkpoint("response", response.statusCode());
                  response.bodyHandler(body -> {
                    int responseCode = response.statusCode();
                    if (responseCode == 200) {
                      log.debug("Mail sent {} to {} response {}", metric.getMessage(), email, body.toString().trim());
                      rc.response().setStatusCode(200).end();
                    } else {
                      log.debug("Mail failed {} with message `{}` to {} response:\n{}", metric.getMessage(), response.statusMessage(), email, body);
                      rc.response().setStatusCode(401)
                          .putHeader("content-type", "application/json")
                          .end(new JsonObject().put("message", "Unable to send email right now.").encode());
                    }
                  });
                } catch (Exception e) {
                  log.error("Exception sending email: " + metric.getMessage(), e);
                  rc.response().setStatusCode(401)
                      .putHeader("content-type", "application/json")
                      .end(new JsonObject().put("message", "Unable to send email right now.").encode());
                }
              }).exceptionHandler(exception -> {
                log.error("Error sending email", exception);
                rc.response().setStatusCode(401)
                    .putHeader("content-type", "application/json")
                    .end(new JsonObject().put("message", "Unable to send email right now.").encode());
              })
              .end(encodedBody);
        })
        .onFailure(throwable -> {
          log.error("Error creating email token for the user", throwable);
          removeSessionCookie(rc);
          rc.response().setStatusCode(401)
              .putHeader("content-type", "application/json")
              .end(new JsonObject().put("message", "Unable to email the login link. Please try again later.").encode());
        });
  }

  private void setSessionCookie(RoutingContext rc, String tokenBase64) {
    rc.response().headers().add(SET_COOKIE, Cookie.cookie("email_session", tokenBase64)
        .setHttpOnly(true)
        .setPath(rc.mountPoint() + "/")
        .setSecure(absoluteContext(config::getString, rc).startsWith("https")).encode());
  }

  private void removeSessionCookie(RoutingContext rc) {
    // Be paranoid to make sure all cookies with our name are deleted regardless of the path
    // (prevents getting "stuck" because an invalid cookie continues to be presented if we
    // miss the path it has)
    String path = "";
    for (String pathComponent : rc.request().path().split("/")) {
      if (pathComponent.length() > 0) {
        path += pathComponent;
        removeSessionCookie(rc, path);
      }
      path += "/";
      removeSessionCookie(rc, path);
    }
  }

  private void removeSessionCookie(RoutingContext rc, String path) {
    rc.response().headers().add(SET_COOKIE, Cookie.cookie("email_session", "")
        .setMaxAge(0)
        .setHttpOnly(true)
        .setPath(path)
        .setSecure(absoluteContext(config::getString, rc).startsWith("https")).encode());
  }
}
