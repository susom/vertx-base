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
package com.github.susom.vertx.base.test;

import com.github.susom.vertx.base.FakeAuthenticator;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpMethod;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import io.vertx.ext.web.Router;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.util.List;
import java.util.function.Function;

/**
 * Tests for cookie Path attribute and cleanup behavior in FakeAuthenticator.
 *
 * <p>These tests verify the subtle browser semantics around multiple cookies
 * with the same name and different paths:
 * <ol>
 *   <li>Cookies (session_token, XSRF-TOKEN, state) are set with Path=/ during
 *       a successful authentication callback.</li>
 *   <li>An authentication failure clears the session_token cookie for all
 *       path prefixes of the request URI to remove legacy cookies that may
 *       have been set with non-root paths.</li>
 * </ol>
 */
@RunWith(VertxUnitRunner.class)
public class FakeAuthenticatorCookieTest {
  private static final Logger log = LoggerFactory.getLogger(FakeAuthenticatorCookieTest.class);
  private Vertx vertx;
  private HttpClient client;

  @Before
  public void setUp(TestContext context) {
    vertx = Vertx.vertx();
    client = vertx.createHttpClient();
  }

  @After
  public void tearDown(TestContext context) {
    if (client != null) {
      client.close();
    }
    if (vertx != null) {
      vertx.close(context.asyncAssertSuccess());
    }
  }

  /**
   * Builds a FakeAuthenticator config function pointing at a specific token server port.
   */
  private Function<String, String> makeConfig(int tokenServerPort) {
    return key -> {
      switch (key) {
        case "root.url":
          return "http://localhost:" + tokenServerPort;
        case "public.url":
          return "http://localhost:" + tokenServerPort;
        case "context.path":
          return "";
        case "insecure.log.full.requests":
          return "false";
        default:
          return null;
      }
    };
  }

  /**
   * Verifies that after a successful OAuth callback the response contains
   * Set-Cookie headers for session_token and XSRF-TOKEN both with {@code Path=/},
   * and that the state cookie is cleared with {@code Path=/}.
   */
  @Test
  public void testCallbackSetsCookiesWithRootPath(TestContext context) throws Exception {
    Async async = context.async();

    // Stand up a minimal token endpoint
    Router tokenRouter = Router.router(vertx);
    tokenRouter.post("/fake-authentication/token").handler(rc -> {
      log.info("Token endpoint received request");
      rc.response()
          .putHeader("content-type", "application/json")
          .end("{\"sub\":\"testuser\",\"name\":\"Test User\",\"authority\":[\"test:read\"]}");
    });

    vertx.createHttpServer()
        .requestHandler(tokenRouter)
        .listen(0, context.asyncAssertSuccess(tokenServer -> {
          int tokenPort = tokenServer.actualPort();
          log.info("Token server started on port {}", tokenPort);

          Router appRouter = Router.router(vertx);
          try {
            FakeAuthenticator auth = new FakeAuthenticator(
                vertx, appRouter, new SecureRandom(), makeConfig(tokenPort));
            Router protected_ = auth.authenticatedRouter("/app");
            protected_.get("/resource").handler(rc -> rc.response().end("ok"));

            vertx.createHttpServer()
                .requestHandler(appRouter)
                .listen(0, context.asyncAssertSuccess(appServer -> {
                  int appPort = appServer.actualPort();
                  log.info("App server started on port {}", appPort);

                  // Trigger the callback with a matching state cookie.
                  // FakeAuthenticator will accept any auth code and return the token.
                  client.request(HttpMethod.GET, appPort, "localhost",
                      "/app/callback?code=anycode&state=teststate123")
                      .compose(req -> {
                        req.putHeader("Cookie", "state=teststate123");
                        return req.send();
                      })
                      .onSuccess(response -> {
                        log.info("Callback status: {}", response.statusCode());
                        List<String> setCookieHeaders = response.headers().getAll("Set-Cookie");
                        log.info("Set-Cookie headers: {}", setCookieHeaders);

                        // session_token must be set with Path=/
                        boolean sessionCookieHasRootPath = setCookieHeaders.stream()
                            .anyMatch(h -> h.startsWith("session_token=")
                                && h.contains("Path=/"));
                        context.assertTrue(sessionCookieHasRootPath,
                            "session_token Set-Cookie header must contain Path=/ but got: "
                                + setCookieHeaders);

                        // XSRF-TOKEN must be set with Path=/
                        boolean xsrfCookieHasRootPath = setCookieHeaders.stream()
                            .anyMatch(h -> h.startsWith("XSRF-TOKEN=")
                                && h.contains("Path=/"));
                        context.assertTrue(xsrfCookieHasRootPath,
                            "XSRF-TOKEN Set-Cookie header must contain Path=/ but got: "
                                + setCookieHeaders);

                        // state must be cleared (Max-Age=0) with Path=/
                        boolean stateClearedWithRootPath = setCookieHeaders.stream()
                            .anyMatch(h -> h.startsWith("state=")
                                && h.contains("Max-Age=0")
                                && h.contains("Path=/"));
                        context.assertTrue(stateClearedWithRootPath,
                            "state Set-Cookie header must be cleared with Path=/ but got: "
                                + setCookieHeaders);

                        async.complete();
                      })
                      .onFailure(err -> {
                        log.error("Callback request failed", err);
                        context.fail(err);
                      });
                }));
          } catch (Exception e) {
            log.error("Failed to create FakeAuthenticator", e);
            context.fail(e);
          }
        }));
  }

  /**
   * Verifies that when a request carries an unrecognized (invalid/expired)
   * session_token cookie, the response clears that cookie for every path
   * prefix of the request URI, not only for {@code Path=/}.
   *
   * <p>For a request to {@code /app/resource} the expected cleared paths are:
   * {@code /}, {@code /app}, {@code /app/}, {@code /app/resource}, {@code /app/resource/}.
   */
  @Test
  public void testAuthFailureClearsCookiesForAllPathPrefixes(TestContext context) throws Exception {
    Async async = context.async();

    Router appRouter = Router.router(vertx);
    // Token server port is irrelevant here; auth fails before reaching it
    FakeAuthenticator auth = new FakeAuthenticator(
        vertx, appRouter, new SecureRandom(), makeConfig(9999));
    Router protected_ = auth.authenticatedRouter("/app");
    protected_.get("/resource").handler(rc -> rc.response().end("should not reach here"));

    vertx.createHttpServer()
        .requestHandler(appRouter)
        .listen(0, context.asyncAssertSuccess(appServer -> {
          int appPort = appServer.actualPort();
          log.info("App server started on port {}", appPort);

          // Send a request with a session cookie whose token is not in any session map
          client.request(HttpMethod.GET, appPort, "localhost", "/app/resource")
              .compose(req -> {
                req.putHeader("Cookie", "session_token=invalid-token-value");
                return req.send();
              })
              .onSuccess(response -> {
                log.info("Auth-failure response status: {}", response.statusCode());
                List<String> setCookieHeaders = response.headers().getAll("Set-Cookie");
                log.info("Set-Cookie headers: {}", setCookieHeaders);

                // The request path is /app/resource.
                // Splitting "/app/resource" by "/" yields ["", "app", "resource"].
                // The loop in WebAppSessionAuthHandler accumulates the path variable, producing
                // Set-Cookie directives for paths: "/", "/app", "/app/", "/app/resource", "/app/resource/"
                String[] expectedPaths = {"/", "/app", "/app/", "/app/resource", "/app/resource/"};
                for (String expectedPath : expectedPaths) {
                  final String ep = expectedPath;
                  boolean found = setCookieHeaders.stream()
                      .anyMatch(h -> h.startsWith("session_token=")
                          && h.contains("Max-Age=0")
                          && h.contains("Path=" + ep));
                  context.assertTrue(found,
                      "Expected session_token to be cleared for Path=" + ep
                          + " but got: " + setCookieHeaders);
                }

                // Response must be 401 since the session is not valid
                context.assertEquals(401, response.statusCode(),
                    "Expected 401 for invalid session token");

                async.complete();
              })
              .onFailure(err -> {
                log.error("Request failed", err);
                context.fail(err);
              });
        }));
  }
}
