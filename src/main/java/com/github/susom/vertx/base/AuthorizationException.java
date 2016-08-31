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

/**
 * Exception to represent when the client lacks enough authority (permission) for
 * this request to the server. It is expected the top level handler for this exception
 * will return an HTTP 403 "Forbidden" (a.k.a. Unauthorized) status code to the client.
 *
 * @author garricko
 */
public class AuthorizationException extends RuntimeException {
  /**
   * @param message this message is expected to be returned to the client
   *                so do not include sensitive information
   */
  public AuthorizationException(String message) {
    super(message);
  }

  /**
   * @param message this message is expected to be returned to the client
   *                so do not include sensitive information
   */
  public AuthorizationException(String message, Throwable cause) {
    super(message, cause);
  }
}
