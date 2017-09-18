/*
 * Copyright 2016 The Board of Trustees of The Leland Stanford Junior University.
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

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;

import org.owasp.encoder.Encode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

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
import io.vertx.ext.jwt.JWT;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.CookieHandler;
import io.vertx.ext.web.impl.CookieImpl;

import static com.github.susom.vertx.base.VertxBase.absoluteContext;
import static com.github.susom.vertx.base.VertxBase.mdc;
import static io.vertx.core.http.HttpHeaders.COOKIE;
import static io.vertx.core.http.HttpHeaders.SET_COOKIE;

// TODO This class is not complete and is not secure yet!!!

/**
 * This class provides authentication services based on an external Keycloak
 * server using the OpenID Connect protocol.
 *
 * <p>WARNING: This is not production ready yet! Do not use for real authentication!</p>
 *
 * @author garricko
 */
public class OidcKeycloakAuthenticator implements Security {
  private static final Logger log = LoggerFactory.getLogger(OidcKeycloakAuthenticator.class);
  private static final Pattern VALID_AUTH_CODE = Pattern.compile("[\\.a-zA-Z0-9_/-]*");
  private static final String DEFAULT_AUTHORITY_SET = "self";
  private final CookieHandler cookieHandler;
  private final Handler<RoutingContext> authenticateOptional;
  private final Handler<RoutingContext> authenticateRequiredOrDeny;
  private final Handler<RoutingContext> authenticateRequiredOrRedirect302;
  private final Handler<RoutingContext> authenticateRequiredOrRedirectJs;
  private final Vertx vertx;
  private final Router root;
  private final SecureRandom secureRandom;
  private final Map<String, Session> sessions = new HashMap<>();
  private final Config config;
  private HttpClient httpClient;
  private String authUrl;
  private String tokenUrl;
  private String logoutUrl;
  private String clientId;
  private String clientSecret;
  private String scope;
  private String publicKey;

  public OidcKeycloakAuthenticator(Vertx vertx, Router root, SecureRandom secureRandom, Function<String, String> cfg) throws Exception {
    this.vertx = vertx;
    this.root = root;
    this.secureRandom = secureRandom;
    config = Config.from().custom(cfg::apply).get();
    String authBaseUri;

    scheduleSessionReaper(vertx);

    authBaseUri = config.getStringOrThrow("auth.server.base.uri");
    authUrl = config.getString("auth.server.login.uri", authBaseUri + "/auth");
    tokenUrl = config.getString("auth.server.token.uri", authBaseUri + "/token");
    logoutUrl = config.getString("auth.server.logout.uri", authBaseUri + "/logout");
    clientId = config.getStringOrThrow("auth.client.id");
    clientSecret = config.getString("auth.client.secret");
    scope = config.getString("auth.client.scope", "openid");
    publicKey = config.getStringOrThrow("auth.server.public.key");

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
    Handler<RoutingContext> optional = WebAppSessionAuthHandler.optional(sessions);
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
    Handler<RoutingContext> mandatory = WebAppSessionAuthHandler.mandatory(sessions, true, rc -> {
      QueryStringEncoder params = new QueryStringEncoder("");

      params.addParam("client_id", clientId);
      params.addParam("response_type", "code");
      params.addParam("scope", scope);
      params.addParam("redirect_uri", redirectUri(rc));
      String state = new TokenGenerator(secureRandom).create(15);
      params.addParam("state", state);

      rc.response().headers().add(SET_COOKIE, io.vertx.ext.web.Cookie.cookie("state", state)
          .setHttpOnly(true)
          .setPath(rc.mountPoint() + "/")
          .setSecure(redirectUri(rc).startsWith("https")).encode());

      String loginUrl = authUrl + params;
      rc.response().setStatusCode(401).putHeader("WWW-Authenticate", "Redirect " + loginUrl)
          .end("401 Authentication Required");
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
    Handler<RoutingContext> mandatoryRedirect = WebAppSessionAuthHandler.mandatory(sessions, true, rc -> {
      QueryStringEncoder params = new QueryStringEncoder("");

      params.addParam("client_id", clientId);
      params.addParam("response_type", "code");
      params.addParam("scope", scope);
      params.addParam("redirect_uri", redirectUri(rc));
      String state = new TokenGenerator(secureRandom).create(15);
      params.addParam("state", state);

      rc.response().headers().add(SET_COOKIE, io.vertx.ext.web.Cookie.cookie("state", state)
          .setHttpOnly(true)
          .setPath(rc.mountPoint() + "/")
          .setSecure(redirectUri(rc).startsWith("https")).encode());

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
    Handler<RoutingContext> mandatoryRedirectJs = WebAppSessionAuthHandler.mandatory(sessions, false, rc -> {
      QueryStringEncoder params = new QueryStringEncoder("");

      params.addParam("client_id", clientId);
      params.addParam("response_type", "code");
      params.addParam("scope", scope);
      params.addParam("redirect_uri", redirectUri(rc));
      String state = new TokenGenerator(secureRandom).create(15);
      params.addParam("state", state);

      rc.response().headers().add(SET_COOKIE, io.vertx.ext.web.Cookie.cookie("state", state)
          .setHttpOnly(true)
          .setPath(rc.mountPoint() + "/")
          .setSecure(redirectUri(rc).startsWith("https")).encode());

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
          + "window.location.href='" + Encode.forJavaScript(authUrl + params) + "';\n"
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

  private void scheduleSessionReaper(Vertx vertx) {
    vertx.setPeriodic(300000L, id -> {
      Metric metric = new Metric(log.isTraceEnabled());
      Instant now = Instant.now();
      List<String> expired = new ArrayList<>(500);
      sessions.forEach((k,v) -> {
        if (v.expires.isBefore(now)) {
          expired.add(k);
        }
      });
      for (String token : expired) {
        sessions.remove(token);
      }
      if (log.isTraceEnabled()) {
        log.trace("Reaped " + expired.size() + " expired sessions " + metric.getMessage());
      }
    });
  }

  @Override
  public Router authenticatedRouter(String mountPoint) {
    Router router = Router.router(vertx);

    // TODO add active defense handler here in front of everything

    // Optimistically pick up logged in user here so logging and metrics will
    // be correctly attributed whenever possible.
    router.route().handler(authenticateOptional());
    router.route().handler(new MetricsHandler(secureRandom, config.getBooleanOrFalse("insecure.log.full.requests")));

    // Add public assets before authentication is required
    router.get("/assets/*").handler(new StrictResourceHandler(vertx).addDir("static/assets-public", "**/*", "assets"));

    // Authentication callback and logout have to be accessible without authenticating
    router.get("/callback").handler(callbackHandler());
    router.get("/logout").handler(logoutHandler());

    // Special case redirect for primary page. This will load a small HTML+JS
    // page and execute some JavaScript to preserve the query string and bookmark
    // before doing a client-side redirect.
    router.get("/").handler(authenticateOrRedirectJs());

    // Lock down everything else to return 401 with WWW-Authenticate: Redirect <login>
    router.route().handler(authenticateOrDeny());

    // Now layer in any assets that should be behind authentication (keep in mind
    // things like source maps will not work for resources here because the browser
    // does not pass session cookies or special headers)
    router.get("/assets/*").handler(new StrictResourceHandler(vertx).addDir("static/assets-private", "**/*", "assets"));

    // Information for the client about whether we are logged in, how to login, etc.
    router.get("/login-status").handler(loginStatusHandler());

    root.mountSubRouter(mountPoint, router);
    return router;
  }

//  @Override
  public Handler<RoutingContext> authenticateOptional() {
    return authenticateOptional;
  }

//  @Override
  public Handler<RoutingContext> authenticateOrDeny() {
    return authenticateRequiredOrDeny;
  }

//  @Override
  public Handler<RoutingContext> authenticateOrRedirect302() {
    return authenticateRequiredOrRedirect302;
  }

//  @Override
  public Handler<RoutingContext> authenticateOrRedirectJs() {
    return authenticateRequiredOrRedirectJs;
  }

  @Override
  public Handler<RoutingContext> requireAuthority(String authority) {
    return rc -> {
      AuthenticatedUser user = AuthenticatedUser.from(rc);
      if (user == null) {
        log.warn("No authenticated user");
        rc.response().setStatusCode(401).end("401 Authentication Required");
      } else {
        user.isAuthorised(authority, r -> {
          if (r.succeeded() && r.result()) {
            rc.next();
          } else {
            log.warn("RequiredAuthorityMissing=\"" + authority + "\" User="
                + user.principal().encode());
            rc.response().setStatusCode(403).end("403 Insufficient Authority");
          }
        });
      }
    };
  }

//  @Override
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
          log.debug("State from parameter does not match cookie (XSRF?)");
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
      enc.addParam("redirect_uri", redirectUri(rc));
      enc.addParam("scope", scope);

      Metric metric = new Metric(log.isDebugEnabled());
      httpClient.postAbs(tokenUrl, mdc(response -> {
        metric.checkpoint("response");
        response.bodyHandler(mdc(body -> {
          try {
            metric.checkpoint("body", body.length());
            if (response.statusCode() == 200) {
              JsonObject json = new JsonObject(body.toString());

              log.warn("Response from token end point: " + json.encodePrettily()); // TODO remove

              String sessionToken = new TokenGenerator(secureRandom).create(64);
              JWT decoder = new JWT(publicKey, false);
              JsonObject id = decoder.decode(json.getString("id_token"));
              // TODO need to verify issuer, audience, etc. per spec

              JsonObject access = decoder.decode(json.getString("access_token"));
              log.warn("id_token: " + id.encodePrettily() + "\naccess_token: " + access.encodePrettily()); // TODO remove

              Session session = new Session();
              session.username = id.getString("preferred_username");
              session.displayName = id.getString("name", id.getString("preferred_username"));
              session.expires = Instant.now().plus(12, ChronoUnit.HOURS);
              AuthoritySet authoritySet = new AuthoritySet();
              authoritySet.actingUsername = session.username;
              authoritySet.actingDisplayName = session.displayName;
              authoritySet.combinedDisplayName = session.displayName;
              // TODO not getting authority from keycloak
//                authoritySet.staticAuthority.addAll(json.getJsonArray("authority").getList());
              session.authoritySets.put(DEFAULT_AUTHORITY_SET, authoritySet);
              sessions.put(sessionToken, session);

              io.vertx.ext.web.Cookie jwtCookie = io.vertx.ext.web.Cookie.cookie("session_token",
                  sessionToken).setHttpOnly(true)
                  .setSecure(redirectUri(rc).startsWith("https"));
              io.vertx.ext.web.Cookie xsrfCookie = io.vertx.ext.web.Cookie.cookie("XSRF-TOKEN",
                  new TokenGenerator(secureRandom).create())
                  .setSecure(redirectUri(rc).startsWith("https"));

              rc.response().headers()
                  .add(SET_COOKIE, jwtCookie.encode())
                  .add(SET_COOKIE, xsrfCookie.encode());
              rc.response().setStatusCode(302).putHeader("location", absoluteContext(config::getString, rc) + "/").end();
            } else {
              log.error("Unexpected response connecting to " + tokenUrl + ": " + response.statusCode() + " "
                  + response.statusMessage() + " body: " + body);
              rc.response().setStatusCode(500).end("Bad response from token endpoint");
            }
          } catch (Exception e) {
            log.error("Unexpected error connecting to " + tokenUrl + ": " + response.statusCode() + " "
                + response.statusMessage() + " body: " + body, e);
            rc.response().setStatusCode(500).end("Bad response from token endpoint");
          } finally {
            log.debug("Request token: {}", metric.getMessage());
          }
        }));
      })).exceptionHandler(mdc(e -> {
        try {
          log.error("Unexpected error connecting to " + tokenUrl, e);
          rc.response().setStatusCode(500).end("Bad response from token endpoint");
        } finally {
          log.debug("Request token: {}", metric.getMessage());
        }
      })).putHeader("content-type", "application/x-www-form-urlencoded")
          .putHeader("X-REQUEST-ID", MDC.get("requestId"))
          .end(enc.toString().substring(1));
    };
  }

//  @Override
  public Handler<RoutingContext> loginStatusHandler() {
    return rc -> {
      AuthenticatedUser user = AuthenticatedUser.from(rc);
      if (user != null) {
        rc.response().end(new JsonObject()
            .put("authenticated", true)
            // TODO issuer; acting principal; authority sets
            .put("accountId", user.getAuthenticatedAs())
            .put("userDisplayName", user.getFullDisplayName()).encode());
      } else {
        QueryStringEncoder params = new QueryStringEncoder("");

        params.addParam("client_id", clientId);
        params.addParam("response_type", "code");
        params.addParam("scope", scope);
        params.addParam("redirect_uri", redirectUri(rc));
        String state = new TokenGenerator(secureRandom).create(15);
        params.addParam("state", state);

        rc.response().headers().add(SET_COOKIE, io.vertx.ext.web.Cookie.cookie("state", state)
            .setHttpOnly(true)
            .setSecure(redirectUri(rc).startsWith("https")).encode());

        rc.response().end(new JsonObject()
            .put("authenticated", false)
            .put("loginUrl", authUrl + params).encode());
      }
    };
  }

//  @Override
  public Handler<RoutingContext> logoutHandler() {
    return rc -> {
      if ("yes".equals(rc.request().getParam("done"))) {
        rc.response().setStatusCode(302).putHeader("Location", VertxBase.absoluteContext(config::getString, rc)).end();
//        rc.response().end("Logout complete");
        return;
      }

      QueryStringEncoder fromEnc = new QueryStringEncoder("");
      fromEnc.addParam("redirect_uri", VertxBase.absolutePath(config::getString, rc) + "?done=yes");

      rc.response().headers()
          .add(SET_COOKIE, io.vertx.ext.web.Cookie.cookie("session_token", "").setMaxAge(0).encode())
          .add(SET_COOKIE, io.vertx.ext.web.Cookie.cookie("XSRF-TOKEN", "").setMaxAge(0).encode())
          .add("location", logoutUrl + fromEnc);
      rc.response().setStatusCode(302).end();
    };
  }

  private String redirectUri(RoutingContext rc) {
    return absoluteContext(config::getString, rc) + "/callback";
  }

  private static class Session {
    Instant expires;
    Instant revoked;
    // TODO user agent, ip, bytes up, bytes down, request counts, errors, maliciousness score, ...

    String username;
    String displayName;
    Map<String, AuthoritySet> authoritySets = new HashMap<>();
  }

  private static class AuthoritySet {
    String actingUsername;
    String actingDisplayName;
    String combinedDisplayName;
    Set<String> staticAuthority = new HashSet<>();
  }

  /**
   * This handler uses secret tokens from a browser cookie ("session_token")
   * to authenticate the user. It supports both optional and mandatory
   * authentication, so you can put an optional one in front of everything
   * to get attributed logging where possible, and a mandatory handler
   * in front of your protected resources.
   *
   * <p>This handler manages the SLF4J MDC context by populating the "userId"
   * (based on authentication) and "windowId" (based on the X-WINDOW-ID header,
   * if present). These are generally not cleared by this handler, as that is
   * left to the MetricsHandler after it finishes logging the response.</p>
   *
   * <p>If enforcement is mandatory, a 401 response will be returned if
   * authentication did not succeed for any reason.</p>
   *
   * <p>If enforcement is mandatory, it will also perform XSRF defenses,
   * matching the cookie named XSRF-TOKEN (if present) against the header
   * named X-XSRF-TOKEN. A 403 response will be returned if the header
   * was not provided or did not match the cookie.</p>
   */
  public static class WebAppSessionAuthHandler implements Handler<RoutingContext> {
    private static final Logger log = LoggerFactory.getLogger(WebAppSessionAuthHandler.class);
    private final Map<String, Session> sessions;
    private final boolean mandatory;
    private final boolean checkXsrf;
    private final Handler<RoutingContext> redirecter;

    private WebAppSessionAuthHandler(Map<String, Session> sessions, boolean mandatory, boolean checkXsrf, Handler<RoutingContext> redirecter) {
      this.sessions = sessions;
      this.mandatory = mandatory;
      this.checkXsrf = checkXsrf;
      this.redirecter = redirecter;
    }

    public static WebAppSessionAuthHandler optional(Map<String, Session> sessions) {
      return new WebAppSessionAuthHandler(sessions, false, false, null);
    }

    public static WebAppSessionAuthHandler mandatory(Map<String, Session> sessions) {
      return new WebAppSessionAuthHandler(sessions, true, true, null);
    }

    public static WebAppSessionAuthHandler mandatory(Map<String, Session> sessions, boolean checkXsrf,
                                                     Handler<RoutingContext> redirectUri) {
      return new WebAppSessionAuthHandler(sessions, true, checkXsrf, redirectUri);
    }

    public void handle(RoutingContext rc) {
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

        if (mandatory && checkXsrf) {
          io.vertx.ext.web.Cookie xsrf = rc.getCookie("XSRF-TOKEN");
          if (xsrf != null) {
            String xsrfHeader = rc.request().getHeader("X-XSRF-TOKEN");
            if (xsrfHeader == null || xsrfHeader.length() == 0) {
              log.debug("Missing XSRF header");
              if (redirecter == null) {
                rc.response().setStatusCode(403).end("Send X-XSRF-TOKEN header with value from XSRF-TOKEN cookie");
              } else {
                redirecter.handle(rc);
              }
              return;
            } else if (!xsrf.getValue().equals(xsrfHeader)) {
              log.debug("XSRF header did not match");
              if (redirecter == null) {
                rc.response().setStatusCode(403).end("The X-XSRF-TOKEN header value did not match the XSRF-TOKEN cookie");
              } else {
                redirecter.handle(rc);
              }
              return;
            }
          }
        }

        io.vertx.ext.web.Cookie sessionCookie = rc.getCookie("session_token");
        if (sessionCookie != null && sessionCookie.getValue() != null) {
          Session session = sessions.get(sessionCookie.getValue());
          // TODO handle case where session is not in our cache and we need to get it from the coordinator
          if (session != null && session.revoked == null && session.expires.isAfter(Instant.now())) {
            MetricsHandler.checkpoint(rc, "auth");
            new AuthenticatedUser(session.username, session.username, session.displayName,
                session.authoritySets.get(DEFAULT_AUTHORITY_SET).staticAuthority).store(rc);
            MDC.put("userId", session.username);
            rc.next();
          } else {
            MetricsHandler.checkpoint(rc, "authFail");
            rc.response().headers().add(SET_COOKIE, sessionCookie.setValue("").setMaxAge(0).encode());
            if (mandatory) {
              if (log.isTraceEnabled()) {
                if (session == null) {
                  log.trace("Session cookie is null");
                } else {
                  log.trace("Session cookie is invalid: expires=" + session.expires + " revoked=" + session.revoked);
                }
              }
              if (redirecter == null) {
                rc.response().setStatusCode(401).end("Session expired");
              } else {
                redirecter.handle(rc);
              }
            } else {
              rc.next();
            }
          }
        } else {
          MetricsHandler.checkpoint(rc, "noAuth");
          if (mandatory) {
            if (redirecter == null) {
              rc.response().setStatusCode(401).end("No session_token cookie");
            } else {
              redirecter.handle(rc);
            }
          } else {
            rc.next();
          }
        }
      }
    }
  }
}
