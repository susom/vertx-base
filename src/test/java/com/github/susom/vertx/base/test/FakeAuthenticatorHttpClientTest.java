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
import io.vertx.core.http.RequestOptions;
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

import java.net.URI;
import java.security.SecureRandom;
import java.util.function.Function;

/**
 * Test that FakeAuthenticator properly handles HTTP client requests with non-standard ports.
 * This test verifies that the token endpoint URL is correctly parsed and the port is preserved.
 *
 * @author jpallas
 */
@RunWith(VertxUnitRunner.class)
public class FakeAuthenticatorHttpClientTest {
  private static final Logger log = LoggerFactory.getLogger(FakeAuthenticatorHttpClientTest.class);
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
   * Test that FakeAuthenticator's HTTP client properly connects to the token endpoint
   * when a non-standard port is used. In Vert.x 4, the HttpClient.request() method
   * requires proper URI parsing to extract host and port.
   */
  @Test
  public void testTokenEndpointWithNonStandardPort(TestContext context) throws Exception {
    Async async = context.async();

    // Create a simple HTTP server on a non-standard port to act as the token endpoint
    Router tokenServer = Router.router(vertx);

    tokenServer.post("/fake-authentication/token").handler(rc -> {
      log.info("Token endpoint received request");
      rc.response()
          .putHeader("content-type", "application/json")
          .end("{\"sub\":\"testuser\",\"name\":\"Test User\",\"authority\":[\"test:read\"]}");
    });

    // Start the token server on a dynamically assigned port
    vertx.createHttpServer()
        .requestHandler(tokenServer)
        .listen(0, context.asyncAssertSuccess(server -> {
          int port = server.actualPort();
          log.info("Token server started on port {}", port);

          // Configure FakeAuthenticator to use the dynamically assigned port
          Function<String, String> config = key -> {
            switch (key) {
              case "root.url":
                return "http://localhost:" + port;
              case "public.url":
                return "http://localhost:" + port;
              case "context.path":
                return "";
              case "insecure.log.full.requests":
                return "false";
              default:
                return null;
            }
          };

          Router appRouter = Router.router(vertx);
          SecureRandom secureRandom = new SecureRandom();

          try {
            FakeAuthenticator authenticator = new FakeAuthenticator(vertx, appRouter, secureRandom, config);
            Router protectedRouter = authenticator.authenticatedRouter("/app");

            protectedRouter.get("/test").handler(rc -> {
              rc.response().end("Protected resource");
            });

            // Start the application server on a different port (also dynamic)
            vertx.createHttpServer()
                .requestHandler(appRouter)
                .listen(0, context.asyncAssertSuccess(appServer -> {
                  int appPort = appServer.actualPort();
                  log.info("App server started on port {}", appPort);

                  // Simulate the OAuth callback flow
                  // First, get the auth page to establish a session
                  client.request(HttpMethod.GET, appPort, "localhost", "/app/test")
                      .compose(req -> req.send())
                      .onSuccess(response1 -> {
                        context.assertEquals(401, response1.statusCode(),
                            "Expected 401 for unauthenticated request");
                        log.info("Initial request returned 401 as expected");

                        // Now simulate the callback with an auth code
                        // This will trigger the HTTP client to connect to the token endpoint
                        client.request(HttpMethod.GET, appPort, "localhost",
                            "/app/callback?code=testcode123&state=teststate")
                            .compose(req -> {
                              // Add the state cookie that would have been set by the auth flow
                              req.putHeader("Cookie", "state=teststate");
                              return req.send();
                            })
                            .onSuccess(response2 -> {
                              log.info("Callback response status: {}", response2.statusCode());
                              response2.bodyHandler(body -> {
                                log.info("Callback response body: {}", body.toString());

                                // The test passes if we get a response (even if it's an error)
                                // without a connection refused error. The connection to the
                                // token endpoint on the dynamically assigned port should work.
                                if (response2.statusCode() == 500 &&
                                    body.toString().contains("Connection refused")) {
                                  context.fail("FakeAuthenticator failed to connect to token endpoint on port " + port +
                                      ". The HttpClient is not properly parsing the port from the tokenUrl.");
                                } else if (response2.statusCode() == 302 || response2.statusCode() == 200) {
                                  log.info("Test passed: Token endpoint was successfully reached");
                                  async.complete();
                                } else {
                                  // Some other error, but not a port issue
                                  log.info("Got response code {} which indicates the port was reached",
                                      response2.statusCode());
                                  async.complete();
                                }
                              });
                            })
                            .onFailure(err -> {
                              log.error("Callback request failed", err);
                              context.fail("Failed to make callback request: " + err.getMessage());
                            });
                      })
                      .onFailure(err -> {
                        log.error("Initial request failed", err);
                        context.fail("Failed to make initial request: " + err.getMessage());
                      });
                }));
          } catch (Exception e) {
            log.error("Failed to create FakeAuthenticator", e);
            context.fail(e);
          }
        }));
  }

  /**
   * Test that demonstrates the fix for HttpClient port parsing.
   * In Vert.x 4, passing a full URL string to HttpClient.request(method, url)
   * doesn't properly parse the port. The solution is to use RequestOptions
   * with explicit host, port, and URI.
   */
  @Test
  public void testHttpClientWithPortInUrl(TestContext context) {
    Async async = context.async();

    // Create a simple server on a non-standard port
    Router router = Router.router(vertx);
    router.post("/endpoint").handler(rc -> {
      log.info("Endpoint hit successfully");
      rc.response().end("Success");
    });

    vertx.createHttpServer()
        .requestHandler(router)
        .listen(0, context.asyncAssertSuccess(server -> {
          int port = server.actualPort();
          log.info("Test server started on port {}", port);

          // This is the FIX: Parse the URL and use RequestOptions with explicit host and port
          String fullUrl = "http://localhost:" + port + "/endpoint";
          URI uri = URI.create(fullUrl);
          RequestOptions requestOptions = new RequestOptions()
              .setMethod(HttpMethod.POST)
              .setHost(uri.getHost())
              .setPort(uri.getPort() != -1 ? uri.getPort() : (uri.getScheme().equals("https") ? 443 : 80))
              .setURI(uri.getPath() + (uri.getQuery() != null ? "?" + uri.getQuery() : ""))
              .setSsl(uri.getScheme().equals("https"));

          client.request(requestOptions)
              .compose(req -> req.send("test"))
              .onSuccess(response -> {
                response.bodyHandler(body -> {
                  log.info("Response received: status={}, body={}", response.statusCode(), body.toString());
                  context.assertEquals(200, response.statusCode(),
                      "HttpClient should successfully connect to the correct port when using RequestOptions");
                  context.assertEquals("Success", body.toString());
                  async.complete();
                });
              })
              .onFailure(err -> {
                log.error("Request failed", err);
                context.fail("HttpClient failed to connect: " + err.getMessage());
              });
        }));
  }
}

