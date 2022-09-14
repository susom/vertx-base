/*
 * Copyright 2022 The Board of Trustees of The Leland Stanford Junior University.
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

import io.vertx.core.Future;

public interface PasswordOnlyValidator {
  /**
   * Check a provided password, and return a proper authenticated user for it,
   * if valid, or null if not.
   *
   * @param password the password to verify, or null/empty string
   * @return a valid authenticated user, or null if the password was not valid
   */
  Future<AuthenticatedUser> authenticate(String password);
}
