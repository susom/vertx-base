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

import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;

/**
 * This interface wraps the basic security services so the application does not
 * need to know what mechanisms are being used.
 *
 * @author garricko
 */
public interface Security {
//  void registerApp(String appName);

  Handler<RoutingContext> authenticateOptional();

  Handler<RoutingContext> authenticateOrDeny();

  Handler<RoutingContext> authenticateOrRedirect302();

  Handler<RoutingContext> authenticateOrRedirectJs();

  Handler<RoutingContext> requireAuthority(String authority);

  Handler<RoutingContext> callbackHandler();

  Handler<RoutingContext> loginStatusHandler();

  Handler<RoutingContext> logoutHandler();
}
