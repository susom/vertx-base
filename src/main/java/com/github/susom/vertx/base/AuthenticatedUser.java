/*
 * Copyright 2016 The Board of Trustees of The Leland Stanford Junior University.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.github.susom.vertx.base;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;

import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authorization.Authorization;
import io.vertx.ext.auth.authorization.Authorizations;
import io.vertx.ext.auth.authorization.PermissionBasedAuthorization;
import io.vertx.ext.auth.authorization.impl.AuthorizationsImpl;
import io.vertx.ext.web.RoutingContext;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Represent a user that has been properly authenticated.
 *
 * @author garricko
 */
public class AuthenticatedUser implements User {
  private static final String DEFAULT_PROVIDER_ID = "default_provider";

  // TODO need to figure out issuer/domain/pk representation
  private final String authenticatedAs;
  private final String actingAs;
  private final String fullDisplayName;
  private final Set<String> authority;
  private final Authorizations authorizations;

  public AuthenticatedUser(String authenticatedAs, String actingAs, String fullDisplayName, Set<String> authority) {
    this.authenticatedAs = authenticatedAs;
    this.actingAs = actingAs;
    this.authority = authority;
    this.fullDisplayName = fullDisplayName == null ? actingAs : fullDisplayName;

    // Convert string authorities to real PermissionBasedAuthorization objects
    // Store them in an Authorizations container with our default provider ID
    this.authorizations = new AuthorizationsImpl();
    for (String auth : authority) {
      this.authorizations.add(DEFAULT_PROVIDER_ID, PermissionBasedAuthorization.create(auth));
    }
  }


  public static AuthenticatedUser from(RoutingContext rc) {
    User user = rc.user();
    if (user instanceof AuthenticatedUser) {
      return (AuthenticatedUser) user;
    }
    return null;
  }

  public static AuthenticatedUser required(RoutingContext rc) {
    User user = rc.user();
    if (user instanceof AuthenticatedUser) {
      return (AuthenticatedUser) user;
    }
    throw new AuthenticationException("No authenticated user");
  }

  public AuthenticatedUser store(RoutingContext rc) {
    rc.setUser(this);
    return this;
  }

  @Override
  public Future<Boolean> isAuthorized(String authority) {
    if (this.authority.contains(authority)) {
      return Future.succeededFuture(true);
    } else {
      return Future.succeededFuture(false);
    }
  }

  /**
   * Check if the user has the specified authority using a callback handler.
   * This is the method that authenticators call in requireAuthority().
   *
   * @param authority the authority string to check (e.g., "service:secret")
   * @param resultHandler the handler that will receive the authorization result
   * @return this User instance for chaining
   */
  @Override
  public User isAuthorized(String authority, Handler<AsyncResult<Boolean>> resultHandler) {
    if (this.authority.contains(authority)) {
      resultHandler.handle(Future.succeededFuture(true));
    } else {
      resultHandler.handle(Future.succeededFuture(false));
    }
    return this;
  }

  @Override
  public User isAuthorized(Authorization authorization, Handler<AsyncResult<Boolean>> resultHandler) {
    // Use the Authorization's match() method - this properly delegates to the Authorization
    // implementation and uses our authorizations() to check if the user has the authorization
    boolean hasAuth = authorization.match(this);
    resultHandler.handle(Future.succeededFuture(hasAuth));
    return this;
  }

  @Override
  public JsonObject principal() {
    return new JsonObject()
        .put("sub", authenticatedAs)
        .put("forsub", actingAs)
        .put("name", fullDisplayName)
        .put("authority", authority.stream().sorted().collect(Collectors.toList()));
  }

  @Override
  public void setAuthProvider(AuthProvider authProvider) {
    // Nothing to do yet
  }

  @Override
  public User merge(User other) {
    if (other == null) {
      return this;
    }
    
    // Create a new set that includes authorities from both users
    Set<String> mergedAuthorities = new HashSet<>(this.authority);
    
    // If the other user is also an AuthenticatedUser, merge its authorities
    if (other instanceof AuthenticatedUser) {
      AuthenticatedUser otherAuth = (AuthenticatedUser) other;
      mergedAuthorities.addAll(otherAuth.authority);
    }
    
    // Return a new AuthenticatedUser with merged authorities
    return new AuthenticatedUser(this.authenticatedAs, this.actingAs, this.fullDisplayName, mergedAuthorities);
  }

  @Override
  public JsonObject attributes() {
    return new JsonObject();
  }

  /**
   * Provide access to the user's authorizations for proper authorization matching.
   * This is used by the Vert.x authorization framework.
   */
  public Authorizations authorizations() {
    return authorizations;
  }

  public String getAuthenticatedAs() {
    return authenticatedAs;
  }

  public String getActingAs() {
    return actingAs;
  }

  public String getFullDisplayName() {
    return fullDisplayName;
  }
}
