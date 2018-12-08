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

import com.github.susom.database.Config;
import com.github.susom.database.Metric;
import io.netty.handler.codec.http.cookie.Cookie;
import io.netty.handler.codec.http.cookie.ServerCookieDecoder;
import io.netty.handler.codec.http.QueryStringEncoder;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.CookieHandler;
import io.vertx.ext.web.impl.CookieImpl;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.*;
import java.util.function.Function;
import org.owasp.encoder.Encode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import static com.github.susom.vertx.base.VertxBase.absoluteContext;
import static io.vertx.core.http.HttpHeaders.COOKIE;
import static io.vertx.core.http.HttpHeaders.SET_COOKIE;

import com.google.common.base.Preconditions;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.interfaces.ECPublicKey;
import java.time.Clock;
import java.net.URL;

/**
 * This class provides IAP authentication services based on Google Cloud Identity Aware Proxy.
 *
 * @author harishk
 */
public class IAPAuthenticator implements Security {
  private static final Logger log = LoggerFactory.getLogger(IAPAuthenticator.class);
  private static final String DEFAULT_AUTHORITY_SET = "self";
  private final Vertx vertx;
  private final Router root;
  private final SecureRandom secureRandom;
  private final Config config;
  private final Map<String, InternalSession> sessions = new HashMap<>();
  private final CookieHandler cookieHandler;
  private final Handler<RoutingContext> authenticateOptional;
  private final Handler<RoutingContext> authenticatedJWTTokenHandler;
  private final String  projectNumber ;
  private final String backendServiceId ;
  private static final String PUBLIC_KEY_VERIFICATION_URL = "https://www.gstatic.com/iap/verify/public_key-jwk";
  private static final String IAP_ISSUER_URL = "https://cloud.google.com/iap";
  private final Map<String, JWK> keyCache = new HashMap<>();
  private final static Clock clock = Clock.systemUTC();

  public IAPAuthenticator(Vertx vertx, Router root, SecureRandom secureRandom, Function<String, String> cfg) throws Exception {
    this.vertx = vertx;
    this.root = root;
    this.secureRandom = secureRandom;
    config = Config.from().custom(cfg::apply).get();

     /**
      * The below two properties are used for the Google Identity Aware Proxy (IAP) authentication.
      * This is used to secure the application with signed Cloud IAP headers.
      * GCP project number in which the IAP protected URL is configured.
      * GCP backend service ID where the IAP protected URL ia mapped.
      */
    projectNumber = config.getStringOrThrow("iap.project.number");
    backendServiceId = config.getStringOrThrow("iap.backend.service.id");

    scheduleSessionReaper(vertx);

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
      if (rc.user() == null) {
        cookieHandler.handle(rc);
        optional.handle(rc);
      } else {
        rc.next();
      }
    };

    Handler<RoutingContext> authenticatedJWT = WebAppSessionAuthHandler.optional(sessions);
    authenticatedJWTTokenHandler = rc -> {
      String email = null;
      if (rc.user() == null) {
        if (rc.request().getHeader("x-goog-iap-jwt-assertion") != null) {
          try {
            //log.trace("Project number : " + projectNumber);
            //log.trace("Backend Service Id : " + backendServiceId);
            if ((rc.request().getHeader("x-goog-iap-jwt-assertion") != null)) {
              email = verifyJwt((rc.request().getHeader("x-goog-iap-jwt-assertion")),
                      String.format("/projects/%s/global/backendServices/%s",
                      Long.toUnsignedString(Long.parseLong(projectNumber)), Long.toUnsignedString(Long.parseLong(backendServiceId))));
            }
          } catch (Exception e) {
            log.trace(e.getMessage());
            e.printStackTrace();
          }
        }
        if (email != null) {
          String sunetID = email.substring(0, email.indexOf("@"));
          String sessionToken = new TokenGenerator(secureRandom).create(64);
          InternalSession session = new IAPAuthenticator.InternalSession();
          session.expires = Instant.now().plus(config.getInteger("iap.session.expiration.minutes", 3600), ChronoUnit.SECONDS);
          session.username = sunetID;
          session.displayName = sunetID;
          AuthoritySet authoritySet = new AuthoritySet();
          authoritySet.actingUsername = session.username;
          authoritySet.actingDisplayName = session.displayName;
          authoritySet.combinedDisplayName = session.displayName;
          // TODO  Revisit the readAuthorityAsList method for reading the authority.
          authoritySet.staticAuthority.addAll(new ArrayList<>());
          session.authoritySets.put(DEFAULT_AUTHORITY_SET, authoritySet);
          sessions.put(sessionToken, session);
          io.vertx.ext.web.Cookie sessionCookie = io.vertx.ext.web.Cookie.cookie("session_token",
                  sessionToken).setHttpOnly(true).setSecure(redirectUri(rc).startsWith("https"));
          io.vertx.ext.web.Cookie xsrfCookie = io.vertx.ext.web.Cookie.cookie("XSRF-TOKEN",
                  new TokenGenerator(secureRandom).create()).setSecure(redirectUri(rc).startsWith("https"));
          rc.response().headers()
            .add(SET_COOKIE, sessionCookie.encode())
            .add(SET_COOKIE, xsrfCookie.encode());
          log.info("Setting session Cookie");
          rc.next();
        } else {
          cookieHandler.handle(rc);
          authenticatedJWT.handle(rc);
        }
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

  /**
   * Verify the JWT token.
   *
   * @param jwtToken contains the JWT token.
   * @param expectedAudience a string in the format /projects/PROJECT_NUMBER/global/backendServices/SERVICE_ID
   *
   * @return email of the logged in user, if the token is valid.
   */
  private String verifyJwt(String jwtToken, String expectedAudience) throws Exception {
    // parse signed token into header / claims
    SignedJWT signedJwt = SignedJWT.parse(jwtToken);
    JWSHeader jwsHeader = signedJwt.getHeader();

    // header must have algorithm("alg") and "kid"
    Preconditions.checkNotNull(jwsHeader.getAlgorithm());
    Preconditions.checkNotNull(jwsHeader.getKeyID());

    JWTClaimsSet claims = signedJwt.getJWTClaimsSet();

    // claims must have audience, issuer
    Preconditions.checkArgument(claims.getAudience().contains(expectedAudience));
    Preconditions.checkArgument(claims.getIssuer().equals(IAP_ISSUER_URL));

    // claim must have issued at time in the past
    Date currentTime = Date.from(Instant.now(clock));
    Preconditions.checkArgument(claims.getIssueTime().before(currentTime));
    // claim must have expiration time in the future
    Preconditions.checkArgument(claims.getExpirationTime().after(currentTime));
    // must have subject, email
    Preconditions.checkNotNull(claims.getSubject());
    Preconditions.checkNotNull(claims.getClaim("email"));
    String email = (String) claims.getClaim("email");

    // verify using public key : lookup with key id, algorithm name provided
    ECPublicKey publicKey = getKey(jwsHeader.getKeyID(), jwsHeader.getAlgorithm().getName());
    Preconditions.checkNotNull(publicKey);
    JWSVerifier jwsVerifier = new ECDSAVerifier(publicKey);
    boolean isTokenValid = signedJwt.verify(jwsVerifier);
    if (isTokenValid) {
      return email;
    } else {
      return null;
    }
  }

  /**
   * Get the Key from KeyID and algorithm using a Public key verification URL.
   *
   * @param kid KeyId
   * @param kid algorithm
   *
   * @return key
   */
  private ECPublicKey getKey(String kid, String alg) throws Exception {
    JWK jwk = keyCache.get(kid);
    if (jwk == null) {
        // update cache loading jwk public key data from The JSON Key Set
      JWKSet jwkSet = JWKSet.load(new URL(PUBLIC_KEY_VERIFICATION_URL));
      for (JWK key : jwkSet.getKeys()) {
        keyCache.put(key.getKeyID(), key);
      }
      jwk = keyCache.get(kid);
    }
    // confirm that algorithm matches
    if (jwk != null && jwk.getAlgorithm().getName().equals(alg)) {
      return ECKey.parse(jwk.toJSONString()).toECPublicKey();
    }
    return null;
  }

  @Override
  public Router authenticatedRouter(String mountPoint) {
    Router router = Router.router(vertx);

    // Optimistically pick up logged in user here so logging and metrics will
    // be correctly attributed whenever possible.
    router.route().handler(authenticateOptional);

    // Add public assets before authentication is required
    router.get("/assets/*").handler(new StrictResourceHandler(vertx).addDir("static/assets-public", "**/*", "assets"));

    // Handler for Verifying the JWT Token
    router.get("/").handler(authenticatedJWTTokenHandler);

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
      rc.next();
    };
  }

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
        rc.response().setStatusCode(401).end("Unable to determine user");
      }
    };
  }

  private String redirectUri(RoutingContext rc) {
    return absoluteContext(config::getString, rc) + "/callback";
  }
    private static class InternalSession {
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
      private final Map<String, InternalSession> sessions;
      private final boolean mandatory;
      private final boolean checkXsrf;
      private final Handler<RoutingContext> redirecter;

      private WebAppSessionAuthHandler(Map<String, InternalSession> sessions, boolean mandatory,
                                       boolean checkXsrf, Handler<RoutingContext> redirecter) {
          this.sessions = sessions;
          this.mandatory = mandatory;
          this.checkXsrf = checkXsrf;
          this.redirecter = redirecter;
      }

      public static WebAppSessionAuthHandler optional(Map<String, InternalSession> sessions) {
          return new WebAppSessionAuthHandler(sessions, false, false, null);
      }

      public static WebAppSessionAuthHandler mandatory(Map<String, InternalSession> sessions, boolean checkXsrf,
                                                                         Handler<RoutingContext> redirecter) {
          return new WebAppSessionAuthHandler(sessions, true, checkXsrf, redirecter);
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
            InternalSession session = sessions.get(sessionCookie.getValue());
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
