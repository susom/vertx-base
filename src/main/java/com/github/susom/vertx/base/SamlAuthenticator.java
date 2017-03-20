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
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.CookieHandler;
import io.vertx.ext.web.impl.CookieImpl;
import java.io.File;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.owasp.encoder.Encode;
import org.pac4j.core.client.Clients;
import org.pac4j.core.client.RedirectAction;
import org.pac4j.core.client.RedirectAction.RedirectType;
import org.pac4j.core.context.Pac4jConstants;
import org.pac4j.core.engine.CallbackLogic;
import org.pac4j.core.engine.DefaultCallbackLogic;
import org.pac4j.core.engine.DefaultSecurityLogic;
import org.pac4j.core.exception.HttpAction;
import org.pac4j.saml.client.SAML2Client;
import org.pac4j.saml.client.SAML2ClientConfiguration;
import org.pac4j.saml.profile.SAML2Profile;
import org.pac4j.vertx.VertxProfileManager;
import org.pac4j.vertx.VertxWebContext;
import org.pac4j.vertx.handler.impl.SecurityHandlerOptions;
import org.pac4j.vertx.http.DefaultHttpActionAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import static com.github.susom.vertx.base.VertxBase.absoluteContext;
import static com.github.susom.vertx.base.VertxBase.executeBlocking;
import static io.vertx.core.http.HttpHeaders.COOKIE;
import static io.vertx.core.http.HttpHeaders.SET_COOKIE;

/**
 * This class provides authentication services based on an external identity provider
 * using the SAML 2.0 HTTP-Redirect protocol.
 *
 * @author garricko
 */
public class SamlAuthenticator implements Security {
  private static final Logger log = LoggerFactory.getLogger(SamlAuthenticator.class);
  private static final String DEFAULT_AUTHORITY_SET = "self";
  private final Vertx vertx;
  private final Router root;
  private final SecureRandom secureRandom;
  private final Config config;
  private final String[] attributeUsername;
  private final String[] attributeDisplayName;
  private final String[] attributeAuthority;
  private final Map<String, InternalSession> sessions = new HashMap<>();
  private final CookieHandler cookieHandler;
  private final Handler<RoutingContext> authenticateOptional;
  private final Handler<RoutingContext> authenticateRequiredOrDeny;
  private final Handler<RoutingContext> authenticateRequiredOrRedirect302;
  private final Handler<RoutingContext> authenticateRequiredOrRedirectJs;
  private final MetricsHandler metricsHandler;

  public SamlAuthenticator(Vertx vertx, Router root, SecureRandom secureRandom, Function<String, String> cfg) throws Exception {
    this.vertx = vertx;
    this.root = root;
    this.secureRandom = secureRandom;
    config = Config.from().custom(cfg).get();
    attributeUsername = config.getString("saml.attribute.username", "urn:mace:dir:attribute-def:uid,uid,urn:oid:1.3.6.1.4.1.5923.1.1.1.6").split(",");
    attributeDisplayName = config.getString("saml.attribute.display.name", "urn:oid:2.16.840.1.113730.3.1.241,urn:mace:dir:attribute-def:displayName,displayName").split(",");
    attributeAuthority = config.getString("saml.attribute.authority", "eduPersonEntitlement,urn:oid:1.3.6.1.4.1.5923.1.1.1.7").split(",");

    scheduleSessionReaper(vertx);

    final SAML2ClientConfiguration samlCfg = new SAML2ClientConfiguration(
        config.getStringOrThrow("saml.keystore.path"),
        config.getStringOrThrow("saml.keystore.password"),
        config.getStringOrThrow("saml.key.password"),
        config.getStringOrThrow("saml.idp.metadata")
    );

    // Optionally allow limiting the authentication lifetime. By default just
    // go with whatever the IDP uses
    int maxLifetime = config.getInteger("saml.max.lifetime.seconds", -1);
    if (maxLifetime > 0) {
      samlCfg.setMaximumAuthenticationLifetime(maxLifetime);
    }

    samlCfg.setServiceProviderEntityId(config.getStringOrThrow("saml.sp.id"));
    samlCfg.setServiceProviderMetadataPath(new File(config.getStringOrThrow("saml.sp.metadata")).getAbsolutePath());
    samlCfg.setDestinationBindingType(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
    SAML2Client saml2Client = new SAML2Client(samlCfg);
    Clients clients = new Clients(config.getStringOrThrow("public.url") + "/saml-callback", saml2Client);
    final org.pac4j.core.config.Config pac4jConfig = new org.pac4j.core.config.Config(clients);
    SecurityHandlerOptions options = new SecurityHandlerOptions().withClients("SAML2Client");
    // Make sure the client has been initialized properly (uses lazy init)
    clients.findClient("SAML2Client");

    cookieHandler = rc -> {
      // This is meant to be called from within one of our other handlers,
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

    Handler<RoutingContext> callbackHandler = rc -> {
      VertxWebContext webContext = new VertxWebContext(rc) {
        public Map<String, String> getResponseHeaders() {
          // Hack to avoid error because the default implementation assume header names are unique,
          // which they aren't because we add multiple Set-Cookie headers
          Map<String, String> headers = new HashMap<>();
          headers.put("Location", rc.response().headers().get("Location"));
          return headers;
        }

        @Override
        public Object getSessionAttribute(String name) {
          if (name.equals("pac4jRequestedUrl")) {
            String relayState = rc.request().getParam("RelayState");
            if (relayState == null) {
              relayState = "";
            } else {
              relayState = new String(Base64.getDecoder().decode(relayState), Charset.forName("UTF-8"));
            }
            String url = absoluteContext(config::getString, rc) + relayState;
            log.trace("Providing pac4jRequestedUrl as {}", url);
            return url;
          }
          log.trace("Returning null for session attribute {}", name);
          return null;
        }

        @Override
        public void setSessionAttribute(String name, Object value) {
          if (name.equals(Pac4jConstants.USER_PROFILES) && value instanceof Map) {
            SAML2Profile profile = (SAML2Profile) ((Map) value).get("SAML2Client");

            log.trace("User profile: {}", profile);

            String sessionToken = new TokenGenerator(secureRandom).create(64);
            InternalSession session = new InternalSession();
            session.username = profileAttributeAsString(profile, attributeUsername);
            if (session.username == null) {
              log.warn("Unable to read username from profile using attributes {}: {}",
                  Arrays.asList(attributeUsername), profile);
              throw new RuntimeException("Could not determine username from SAML response");
            }
            session.displayName = profileAttributeAsString(profile, attributeDisplayName);
            if (session.displayName == null) {
              session.displayName = session.username;
            }
            session.expires = Instant.now().plus(config.getInteger("saml.session.expiration.minutes", 720), ChronoUnit.MINUTES);
            AuthoritySet authoritySet = new AuthoritySet();
            authoritySet.actingUsername = session.username;
            authoritySet.actingDisplayName = session.displayName;
            authoritySet.combinedDisplayName = session.displayName;
            authoritySet.staticAuthority.addAll(readAuthorityAsList(profile, attributeAuthority));
            session.authoritySets.put(DEFAULT_AUTHORITY_SET, authoritySet);
            sessions.put(sessionToken, session);

            io.vertx.ext.web.Cookie sessionCookie = io.vertx.ext.web.Cookie.cookie("session_token",
                sessionToken).setHttpOnly(true)
                .setSecure(redirectUri(rc).startsWith("https"));
            io.vertx.ext.web.Cookie xsrfCookie = io.vertx.ext.web.Cookie.cookie("XSRF-TOKEN",
                new TokenGenerator(secureRandom).create())
                .setSecure(redirectUri(rc).startsWith("https"));

            rc.response().headers()
                .add(SET_COOKIE, sessionCookie.encode())
                .add(SET_COOKIE, xsrfCookie.encode());
          } else {
            log.trace("Ignoring set session attribute {}={}", name, value);
          }
        }
      };

      CallbackLogic<Void, VertxWebContext> callbackLogic = new DefaultCallbackLogic<>();
      cookieHandler.handle(rc);
      executeBlocking(vertx, future -> {
        callbackLogic.perform(webContext, pac4jConfig, new DefaultHttpActionAdapter(),
            null, false, false);
      }, after -> {
        if (after.failed()) {
          rc.fail(after.cause());
        }
      });
    };

    Handler<RoutingContext> mandatory = WebAppSessionAuthHandler.mandatory(sessions, true, rc -> {
      DefaultSecurityLogic<Void, VertxWebContext> securityLogic = new DefaultSecurityLogic<>();
      securityLogic.setProfileManagerFactory(VertxProfileManager::new);
      VertxWebContext webContext = new VertxWebContext(rc) {
        @Override
        public Object getSessionAttribute(String name) {
          if (name.equals("samlRelayState")) {
            return relayStateForUri(rc);
          }
          log.trace("Returning null for session attribute {}", name);
          return null;
        }

        @Override
        public void setSessionAttribute(String name, Object value) {
          log.trace("Ignoring set session attribute {}={}", name, value);
        }

        @Override
        public void failResponse(int status) {
          rc.response().setStatusCode(401).putHeader("WWW-Authenticate", "Redirect")
              .end("401 Authentication Required");
        }
      };

      executeBlocking(vertx, future -> {
        try {
          securityLogic.perform(webContext, pac4jConfig, (ctx, parameters) -> {
                future.complete();
                return null;
              }, new DefaultHttpActionAdapter(), options.clients(), options.authorizers(),
              options.matchers(), options.multiProfile());
        } catch (Exception e) {
          future.fail(e);
        }
      }, after -> {
        if (after.succeeded()) {
          log.trace("Allowing access", after.cause());
          rc.next();
        } else {
          log.warn("Denying access", after.cause());
          rc.response().setStatusCode(401).putHeader("WWW-Authenticate", "Redirect")
              .end("401 Authentication Required");
        }
      });
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
      VertxWebContext webContext = new VertxWebContext(rc) {
        @Override
        public Object getSessionAttribute(String name) {
          if (name.equals("samlRelayState")) {
            return relayStateForUri(rc);
          }
          log.trace("Returning null for session attribute {}", name);
          return null;
        }

        @Override
        public void setSessionAttribute(String name, Object value) {
          log.trace("Ignoring set session attribute {}={}", name, value);
        }
      };

      RedirectAction action;
      try {
        action = saml2Client.getRedirectAction(webContext);
      } catch (HttpAction e) {
        throw new RuntimeException("Error before redirect", e);
      }

      if (action.getType() == RedirectType.REDIRECT) {
        rc.response().setStatusCode(302).putHeader("location", action.getLocation()).end();
      } else {
        throw new RuntimeException("Not supporting 200 redirect");
      }
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
      log.debug("Sending client-side JavaScript redirect for SAML authentication");
      // TODO add test cookie and client-side cookie check with error message
      rc.response().putHeader("content-type", "text/html").end("<!DOCTYPE html><html><head>"
          + "<link rel=\"icon\" type=\"image/png\" href=\"data:image/png;base64,iVBORw0KGgo=\"></head><body>"
          + "<noscript>\n"
          + "  <div style=\"width: 22em; position: absolute; left: 50%; margin-left: -11em; "
          + "color: red; background-color: white; border: 1px solid red; padding: 4px; font-family: sans-serif\">\n"
          + "    Your web browser must have JavaScript enabled\n"
          + "    in order for this application to display correctly.\n"
          + "  </div>\n"
          + "</noscript>"
          + "<script type=\"application/javascript\">\n"
          + "var match = window.name.match(/windowId:([^;]+).*/);\n"
          + "if(match){window.name=\"windowId:\"+match[1]+\";q=\"+window.location.search+window.location.hash}\n"
          + "else{window.name=\"windowId:\"+Math.floor(Math.random()*1e16).toString(36).slice(0, 8)"
          + "+\";q=\"+window.location.search+window.location.hash}\n"
          + "window.location.href='" + Encode.forJavaScript(absoluteContext(config::getString, rc) + "/login") + "';\n"
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

    // TODO add active defense handler here in front of callback

    // Authentication callback and logout have to be accessible without authenticating
    // Add the callback at the root level because we share one authentication context
    // between the various sub-routers
    metricsHandler = new MetricsHandler(secureRandom, config.getBooleanOrFalse("insecure.log.full.requests"));
    if (config.getBooleanOrFalse("saml.log.forwarded.ip")) {
      metricsHandler.logXForwardedFor();
    }
    if (config.getBooleanOrFalse("saml.log.user.agent")) {
      metricsHandler.logUserAgent();
    }
    root.post("/saml-callback").handler(authenticateOptional);
    root.post("/saml-callback").handler(metricsHandler);
    root.post("/saml-callback").handler(new StrictBodyHandler(config.getInteger("saml.callback.limit.bytes", 256000)).multipartMergeForm());
    root.post("/saml-callback").handler(callbackHandler);
  }

  private String relayStateForUri(RoutingContext rc) {
    String uri = rc.request().uri();
    if (uri.endsWith("/login")) {
      uri = uri.substring(0, uri.length() - 5);
    }
    if (uri.startsWith("/")) {
      uri = uri.substring(1);
    }
    if (!uri.contains("/")) {
      uri = uri + "/";
    }
    log.trace("Returning uri for samlRelayState: {}", uri);
    return new String(Base64.getEncoder().encode(uri.getBytes(Charset.forName("UTF-8"))), Charset.forName("UTF-8"));
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
    router.route().handler(authenticateOptional);
    router.route().handler(metricsHandler);

    // Add public assets before authentication is required
    router.get("/assets/*").handler(new StrictResourceHandler(vertx).addDir("static/assets-public", "**/*", "assets"));

    // Note the callback handler is added to the root context in the constructor above

    // TODO implement logout handler
//    router.get("/logout").handler(...);

    // Special case redirect for primary page. This will load a small HTML+JS
    // page and execute some JavaScript to preserve the query string and bookmark
    // before doing a client-side redirect.
    router.get("/").handler(authenticateRequiredOrRedirectJs);
    // For SAML the client-side JS redirect doesn't know the URL of the IDP yet,
    // so it sends us back to a local /login url which will do the SAML redirect
    router.get("/login").handler(authenticateRequiredOrRedirect302);
    // If they hit login and have already authenticated, send them back to the top
    router.get("/login").handler(rc -> rc.response().setStatusCode(302).putHeader("Location", mountPoint + "/").end());

    // Lock down everything else to return 401 with WWW-Authenticate: Redirect <login>
    router.route().handler(authenticateRequiredOrDeny);

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

//    public static WebAppSessionAuthHandler mandatory(Map<String, InternalSession> sessions) {
//      return new WebAppSessionAuthHandler(sessions, true, true, null);
//    }

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

  private String profileAttributeAsString(SAML2Profile profile, String[] names) {
    for (String name : names) {
      Object value = profile.getAttribute(name);
      if (value == null) {
        continue;
      }

      if (value instanceof List) {
        List list = (List) value;
        return list.size() > 0 ? list.get(0).toString() : null;
      } else {
        return value.toString();
      }
    }
    return null;
  }

  /**
   * Read user authority from one or more of a specified set of SAML attributes, optionally
   * doing some filtering and substitution based on prefixes.
   *
   * @param profile contains the SAML attributes we want to use
   * @param names a precedence ordered list of attributes (first attribute present will be
   *              used, rest will be ignored), with optional prefix inclusion/substitution
   *              pattern (e.g. "attr1,attr2(prefixToInclude,anotherToInclude),attr3(prefixToReplace->withThis)")
   * @return a list of authorities the user should be granted
   */
  public static List<String> readAuthorityAsList(SAML2Profile profile, String[] names) {
    for (String name : names) {
      String[] prefixes = new String[0];
      if (name.indexOf('(') > 0 && name.indexOf('(') < name.indexOf(')')) {
        prefixes = name.substring(name.indexOf('(') + 1, name.indexOf(')')).split(",");
        name = name.substring(0, name.indexOf('('));
      }
      Object value = profile.getAttribute(name);
      if (value == null) {
        continue;
      }

      if (value instanceof List) {
        List list = (List) value;
        List<String> result = new ArrayList<>();
        for (Object o : list) {
          String authority = o.toString();
          if (prefixes.length == 0) {
            result.add(authority);
          } else {
            for (String prefix : prefixes) {
              if (prefix.contains("->")) {
                String oldPrefix = prefix.substring(0, prefix.indexOf("->"));
                String newPrefix = prefix.substring(prefix.indexOf("->") + 2);

                if (authority.startsWith(oldPrefix)) {
                  result.add(newPrefix + authority.substring(oldPrefix.length()));
                }
              } else {
                if (authority.startsWith(prefix)) {
                  result.add(authority);
                }
              }
            }
          }
        }
        return result;
      } else {
        log.warn("Skipping attribute {}: expected List but got {}", name, value.getClass().getName());
      }
    }
    return new ArrayList<>();
  }
}
