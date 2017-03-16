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
import io.vertx.ext.auth.AbstractUser;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.User;
import io.vertx.ext.web.RoutingContext;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Represent a user that has been properly authenticated.
 *
 * @author garricko
 */
public class AuthenticatedUser extends AbstractUser {
  // TODO need to figure out issuer/domain/pk representation
  private final String authenticatedAs;
  private final String actingAs;
  private final String fullDisplayName;
  private final Set<String> authority;

  public AuthenticatedUser(String authenticatedAs, String actingAs, String fullDisplayName, Set<String> authority) {
    this.authenticatedAs = authenticatedAs;
    this.actingAs = actingAs;
    this.authority = authority;
    this.fullDisplayName = fullDisplayName == null ? actingAs : fullDisplayName;
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
  protected void doIsPermitted(String permission, Handler<AsyncResult<Boolean>> resultHandler) {
    if (authority.contains(permission)) {
      resultHandler.handle(Future.succeededFuture(true));
    } else {
      resultHandler.handle(Future.succeededFuture(false));
    }
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
