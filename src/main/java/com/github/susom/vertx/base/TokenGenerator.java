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

import com.github.susom.database.Metric;
import java.security.SecureRandom;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Generate tokens using cryptographically secure random number generator.
 * These tokens are intended to be suitable for session keys, OAuth tokens,
 * one-time use codes, etc.
 *
 * @author garricko
 */
public class TokenGenerator {
  private static final Logger log = LoggerFactory.getLogger(TokenGenerator.class);
  private final SecureRandom secureRandom;

  public TokenGenerator(SecureRandom secureRandom) {
    this.secureRandom = secureRandom;
  }

  /**
   * Create a token of the specified length (in characters). The returned
   * token will use only the ASCII characters a-z, A-Z, and 0-9 and will
   * encode a secure random number.
   */
  public String create(int length) {
    Metric metric = new Metric(log.isDebugEnabled());
    StringBuilder key = new StringBuilder();

    while (key.length() < length) {
      key.append(Long.toString(Math.abs(secureRandom.nextLong()), Character.MAX_RADIX));
    }

    if (log.isDebugEnabled() && metric.elapsedMillis() > 50) {
      log.debug("Slow token generation: " + metric.getMessage());
    }

    return key.toString().substring(0, length);
  }

  /**
   * Create a session key with a default length (currently 80 characters).
   */
  public String create() {
    return create(80);
  }
}
