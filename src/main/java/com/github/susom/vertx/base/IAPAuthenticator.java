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
import com.google.common.base.Preconditions;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import java.net.URL;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

/**
 * This class provides IAP authentication services based on Google Cloud Identity Aware Proxy.
 *
 * @author harishk
 */
public class IAPAuthenticator implements Security {
  private static final Logger log = LoggerFactory.getLogger(IAPAuthenticator.class);
  private final Vertx vertx;
  private final Router root;
  private final String aud;
  private static final String PUBLIC_KEY_VERIFICATION_URL = "https://www.gstatic.com/iap/verify/public_key-jwk";
  private static final String IAP_ISSUER_URL = "https://cloud.google.com/iap";
  private static final String IAP_JWT_HEADER = "x-goog-iap-jwt-assertion";
  private final Map<String, JWK> keyCache = new HashMap<>();
  private final static Clock clock = Clock.systemUTC();

  public IAPAuthenticator(Vertx vertx, Router root, SecureRandom secureRandom, Function<String, String> cfg) throws Exception {
    this.vertx = vertx;
    this.root = root;
    Config config = Config.from().custom(cfg).get();

    /*
     * The below two properties are used for the Google Identity Aware Proxy (IAP) authentication.
     * This is used to secure the application with signed Cloud IAP headers.
     * GCP project number in which the IAP protected URL is configured.
     * GCP backend service ID where the IAP protected URL ia mapped.
     */
    String projectNumber = config.getStringOrThrow("iap.project.number");
    String backendServiceId = config.getStringOrThrow("iap.backend.service.id");
    aud = String.format("/projects/%s/global/backendServices/%s",
                        Long.toUnsignedString(Long.parseLong(projectNumber)),
                        Long.toUnsignedString(Long.parseLong(backendServiceId)));

    // Load the set of allowed public keys for JWT signature verification and cache them
    JWKSet jwkSet = JWKSet.load(new URL(PUBLIC_KEY_VERIFICATION_URL));
    for (JWK key : jwkSet.getKeys()) {
      keyCache.put(key.getKeyID(), key);
    }
  }

  @Override
  public Router authenticatedRouter(String mountPoint) {
    Router router = Router.router(vertx);

    // Optimistically pick up logged in user here so logging and metrics will
    // be correctly attributed whenever possible.
    router.route().handler(rc -> {
      if (rc.request().getHeader(IAP_JWT_HEADER) == null) {
        log.error("Did not receive the {} header - check your IAP configuration.", IAP_JWT_HEADER);
        rc.response().setStatusCode(500).end("Internal Server Error");
      } else {
        try {
          String email = verifyJwt(rc.request().getHeader(IAP_JWT_HEADER), aud);
          if (email == null) {
            log.error("Couldn't read subject when verifying JWT token");
            rc.response().setStatusCode(401).end("Authentication Required (No Subject)");
          } else {
            new AuthenticatedUser(email, email, email, Collections.emptySet()).store(rc);
            log.trace("Authenticated as {}", email);
            MDC.put("userId", email);
            String windowId = rc.request().getHeader("X-WINDOW-ID");
            if (windowId != null && windowId.matches("[a-zA-Z0-9]{1,32}")) {
              MDC.put("windowId", windowId);
            } else {
              MDC.remove("windowId");
            }
            rc.next();
          }
        } catch (Exception e) {
          log.error("Unable to verify JWT token with aud {}", aud, e);
          rc.response().setStatusCode(401).end("Authentication Required (Unable to Verify)");
        }
      }
    });

    // Serve "public" assets, but they aren't really public in the IAP case
    router.get("/assets/*").handler(new StrictResourceHandler(vertx).addDir("static/assets-public", "**/*", "assets"));

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
            log.warn("RequiredAuthorityMissing=\"" + authority + "\" User="
                + user.principal().encode());
            rc.response().setStatusCode(403).end("403 Insufficient Authority");
          }
        });
      }
    };
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
        rc.response().setStatusCode(401).end("Unable to determine user");
      }
    };
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
   * @param alg algorithm
   *
   * @return key
   */
  private ECPublicKey getKey(String kid, String alg) throws Exception {
    JWK jwk = keyCache.get(kid);
    // confirm that algorithm matches
    if (jwk != null && jwk.getAlgorithm().getName().equals(alg)) {
      return ECKey.parse(jwk.toJSONString()).toECPublicKey();
    }
    return null;
  }
}
