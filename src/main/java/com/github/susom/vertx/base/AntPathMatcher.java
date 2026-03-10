/*
 * Copyright 2026 The Board of Trustees of The Leland Stanford Junior University.
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

/**
 * Minimal Ant-style glob matcher used by {@link StrictResourceHandler} and
 * {@link StrictFileHandler}.
 *
 * <p>Supported wildcards:
 * <ul>
 *   <li>{@code ?}  – matches exactly one character (not {@code /})
 *   <li>{@code *}  – matches zero or more characters within a single path segment (not {@code /})
 *   <li>{@code **} – matches zero or more path segments (may cross {@code /} boundaries)
 * </ul>
 */
class AntPathMatcher {

  /**
   * Returns {@code true} if {@code path} matches the Ant-style glob {@code pattern}.
   */
  static boolean match(String pattern, String path) {
    return matchHelper(pattern, 0, path, 0);
  }

  private static boolean matchHelper(String pattern, int pi, String path, int si) {
    while (pi < pattern.length() && si < path.length()) {
      char p = pattern.charAt(pi);
      if (p == '*') {
        if (pi + 1 < pattern.length() && pattern.charAt(pi + 1) == '*') {
          // '**' – skip the double-star token (and any trailing '/')
          int afterStars = pi + 2;
          if (afterStars < pattern.length() && pattern.charAt(afterStars) == '/') {
            afterStars++;
          }
          if (afterStars == pattern.length()) {
            // '**' at the end matches everything remaining
            return true;
          }
          // Try matching the rest of the pattern against every suffix of the path
          for (int i = si; i <= path.length(); i++) {
            if (matchHelper(pattern, afterStars, path, i)) {
              return true;
            }
          }
          return false;
        } else {
          // Single '*' – matches zero or more non-'/' characters
          int afterStar = pi + 1;
          for (int i = si; i <= path.length(); i++) {
            if (i > si && path.charAt(i - 1) == '/') {
              break; // single '*' cannot cross a '/'
            }
            if (matchHelper(pattern, afterStar, path, i)) {
              return true;
            }
          }
          return false;
        }
      } else if (p == '?') {
        if (path.charAt(si) == '/') {
          return false; // '?' does not match '/'
        }
        pi++;
        si++;
      } else {
        if (p != path.charAt(si)) {
          return false;
        }
        pi++;
        si++;
      }
    }

    // Consume any trailing '**/' tokens that can match empty segments
    while (pi < pattern.length()) {
      if (pattern.charAt(pi) == '*' || pattern.charAt(pi) == '/') {
        pi++;
      } else {
        break;
      }
    }

    return pi == pattern.length() && si == path.length();
  }
}
