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

import com.github.susom.vertx.base.AuthenticatedUser;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpMethod;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.Set;

/**
 * Test FakeAuthentication and AuthenticatedUser authority checking.
 *
 * @author jpallas
 */
@RunWith(VertxUnitRunner.class)
public class FakeAuthenticationTest {
  private static final Logger log = LoggerFactory.getLogger(FakeAuthenticationTest.class);
  private Vertx vertx;
  private HttpClient client;
  private int port = 8765;

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
   * Test that requireAuthority properly checks user authorities.
   * This test simulates what FakeAuthenticator.requireAuthority() does.
   */
  @Test
  public void testRequireAuthority(TestContext context) {
    Async async = context.async();

    // Create a user with specific authorities
    Set<String> authorities = new HashSet<>();
    authorities.add("service:public");
    authorities.add("service:read");
    AuthenticatedUser userWithAuth = new AuthenticatedUser(
        "testuser@example.com",
        "testuser@example.com",
        "Test User",
        authorities
    );

    // Create a user without the required authority
    Set<String> limitedAuthorities = new HashSet<>();
    limitedAuthorities.add("service:public");
    AuthenticatedUser userWithoutAuth = new AuthenticatedUser(
        "limited@example.com",
        "limited@example.com",
        "Limited User",
        limitedAuthorities
    );

    // Create a simple router with a protected endpoint
    Router router = Router.router(vertx);

    // Simulate the requireAuthority handler
    String requiredAuthority = "service:secret";
    Handler<RoutingContext> requireAuthorityHandler = rc -> {
      AuthenticatedUser user = AuthenticatedUser.from(rc);
      if (user == null) {
        log.warn("No authenticated user");
        rc.response().setStatusCode(401).end("401 Authentication Required");
      } else {
        user.isAuthorized(requiredAuthority, r -> {
          if (r.succeeded() && r.result()) {
            rc.next();
          } else {
            log.warn("RequiredAuthorityMissing=\"" + requiredAuthority + "\" User="
                + user.principal().encode());
            rc.response().setStatusCode(403).end("403 Insufficient Authority");
          }
        });
      }
    };

    // Endpoint that requires service:secret authority
    router.get("/secret").handler(requireAuthorityHandler);
    router.get("/secret").handler(rc -> {
      rc.response().end("Secret data");
    });

    // Endpoint for user with authority
    router.get("/with-auth").handler(rc -> {
      userWithAuth.store(rc);
      rc.next();
    });
    router.get("/with-auth").handler(requireAuthorityHandler);
    router.get("/with-auth").handler(rc -> {
      rc.response().end("Authorized");
    });

    // Endpoint for user without authority
    router.get("/without-auth").handler(rc -> {
      userWithoutAuth.store(rc);
      rc.next();
    });
    router.get("/without-auth").handler(requireAuthorityHandler);
    router.get("/without-auth").handler(rc -> {
      rc.response().end("Should not reach here");
    });

    // Start the server
    vertx.createHttpServer()
        .requestHandler(router)
        .listen(port, context.asyncAssertSuccess(server -> {
          log.info("Test server started on port {}", port);

          // Test 1: No authenticated user should return 401
          client.request(HttpMethod.GET, port, "localhost", "/secret")
              .compose(req -> req.send())
              .onSuccess(response1 -> {
                context.assertEquals(401, response1.statusCode(), "Expected 401 for unauthenticated request");
                log.info("Test 1 passed: Unauthenticated request returned 401");

                // Test 2: User without authority should return 403
                client.request(HttpMethod.GET, port, "localhost", "/without-auth")
                    .compose(req -> req.send())
                    .onSuccess(response2 -> {
                      context.assertEquals(403, response2.statusCode(),
                          "Expected 403 for user without required authority");
                      log.info("Test 2 passed: User without authority returned 403");

                      // Test 3: User with authority should return 200
                      // Create a user with the required authority
                      Set<String> secretAuthorities = new HashSet<>();
                      secretAuthorities.add("service:secret");
                      AuthenticatedUser authorizedUser = new AuthenticatedUser(
                          "authorized@example.com",
                          "authorized@example.com",
                          "Authorized User",
                          secretAuthorities
                      );

                      // Add an endpoint for the authorized user
                      router.get("/authorized").handler(rc -> {
                        authorizedUser.store(rc);
                        rc.next();
                      });
                      router.get("/authorized").handler(requireAuthorityHandler);
                      router.get("/authorized").handler(rc -> {
                        rc.response().end("Success");
                      });

                      client.request(HttpMethod.GET, port, "localhost", "/authorized")
                          .compose(req -> req.send())
                          .onSuccess(response3 -> {
                            context.assertEquals(200, response3.statusCode(),
                                "Expected 200 for user with required authority");
                            response3.bodyHandler(body -> {
                              context.assertEquals("Success", body.toString());
                              log.info("Test 3 passed: User with authority returned 200");
                              async.complete();
                            });
                          })
                          .onFailure(err -> {
                            log.error("Test 3 failed", err);
                            context.fail(err);
                          });
                    })
                    .onFailure(err -> {
                      log.error("Test 2 failed", err);
                      context.fail(err);
                    });
              })
              .onFailure(err -> {
                log.error("Test 1 failed", err);
                context.fail(err);
              });
        }));
  }

  /**
   * Test AuthenticatedUser.isAuthorized with Future-based API.
   */
  @Test
  public void testIsAuthorizedFuture(TestContext context) {
    Async async = context.async();

    // Create a user with specific authorities
    Set<String> authorities = new HashSet<>();
    authorities.add("service:read");
    authorities.add("service:write");
    authorities.add("admin:users");

    AuthenticatedUser user = new AuthenticatedUser(
        "testuser@example.com",
        "testuser@example.com",
        "Test User",
        authorities
    );

    // Test existing authority
    user.isAuthorized("service:read").onComplete(context.asyncAssertSuccess(result -> {
      context.assertTrue(result, "User should have service:read authority");
      log.info("User has service:read authority: {}", result);

      // Test another existing authority
      user.isAuthorized("admin:users").onComplete(context.asyncAssertSuccess(result2 -> {
        context.assertTrue(result2, "User should have admin:users authority");
        log.info("User has admin:users authority: {}", result2);

        // Test non-existing authority
        user.isAuthorized("service:delete").onComplete(context.asyncAssertSuccess(result3 -> {
          context.assertFalse(result3, "User should NOT have service:delete authority");
          log.info("User has service:delete authority: {}", result3);
          async.complete();
        }));
      }));
    }));
  }

  /**
   * Test AuthenticatedUser.isAuthorized with callback-based API.
   */
  @Test
  public void testIsAuthorizedCallback(TestContext context) {
    Async async = context.async();

    // Create a user with specific authorities
    Set<String> authorities = new HashSet<>();
    authorities.add("role:admin");
    authorities.add("role:user");

    AuthenticatedUser user = new AuthenticatedUser(
        "admin@example.com",
        "admin@example.com",
        "Admin User",
        authorities
    );

    // Test with callback handler - explicitly use String-based method
    user.isAuthorized("role:admin").onComplete(r -> {
      context.assertTrue(r.succeeded(), "Authorization check should succeed");
      context.assertTrue(r.result(), "User should have role:admin authority");

      user.isAuthorized("role:superadmin").onComplete(r2 -> {
        context.assertTrue(r2.succeeded(), "Authorization check should succeed");
        context.assertFalse(r2.result(), "User should NOT have role:superadmin authority");
        async.complete();
      });
    });
  }

  /**
   * Test that the principal() method returns correct information.
   */
  @Test
  public void testPrincipal(TestContext context) {
    Set<String> authorities = new HashSet<>();
    authorities.add("service:read");
    authorities.add("service:write");

    AuthenticatedUser user = new AuthenticatedUser(
        "user@example.com",
        "actinguser@example.com",
        "Test User Display Name",
        authorities
    );

    var principal = user.principal();
    context.assertEquals("user@example.com", principal.getString("sub"));
    context.assertEquals("actinguser@example.com", principal.getString("forsub"));
    context.assertEquals("Test User Display Name", principal.getString("name"));
    context.assertNotNull(principal.getJsonArray("authority"));
    context.assertEquals(2, principal.getJsonArray("authority").size());

    log.info("Principal: {}", principal.encodePrettily());
  }

  /**
   * Test AuthenticatedUser.isAuthorized with Authorization object and callback handler.
   * This tests the isAuthorized(Authorization, Handler) method.
   */
  @Test
  public void testIsAuthorizedWithAuthorizationObject(TestContext context) {
    Async async = context.async();

    // Create a user with specific authorities
    Set<String> authorities = new HashSet<>();
    authorities.add("role:admin");
    authorities.add("service:read");
    authorities.add("service:write");

    AuthenticatedUser user = new AuthenticatedUser(
        "testuser@example.com",
        "testuser@example.com",
        "Test User",
        authorities
    );

    // Create Authorization instances using PermissionBasedAuthorization
    var adminAuth = PermissionBasedAuthorization.create("role:admin");
    var missingAuth = PermissionBasedAuthorization.create("role:superuser");

    // Test with Authorization object that user has
    user.isAuthorized(adminAuth, r -> {
      context.assertTrue(r.succeeded(), "Authorization check should succeed");
      context.assertTrue(r.result(), "User should have role:admin authority");
      log.info("User has {} authority: {}", adminAuth, r.result());

      // Test with Authorization object that user doesn't have
      user.isAuthorized(missingAuth, r2 -> {
        context.assertTrue(r2.succeeded(), "Authorization check should succeed");
        context.assertFalse(r2.result(), "User should NOT have role:superuser authority");
        log.info("User has {} authority: {}", missingAuth, r2.result());
        async.complete();
      });
    });
  }
}

