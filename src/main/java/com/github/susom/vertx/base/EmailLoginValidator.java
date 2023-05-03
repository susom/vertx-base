/*
 * Copyright 2023 The Board of Trustees of The Leland Stanford Junior University.
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

public interface EmailLoginValidator {
  /**
   * Check a provided token, and return a proper authenticated user for it,
   * if valid, or null if not.
   *
   * @param token the secure unique token to verify, or null/empty string
   * @return a valid authenticated user, or null if the token was not valid, expired, etc.
   */
  Future<AuthenticatedUser> authenticate(String token);

  /**
   * Verify the provided email address is acceptable, and generate a
   * secure unique token to include in the email link. The future can
   * return null or empty to indicate no email should be sent. We do
   * not distinguish the reasons for security purposes.
   *
   * @param email the email address the user requested we send a link
   * @return the token to include in the email link, or null/empty
   */
  Future<String> generateEmailToken(String email);
}
