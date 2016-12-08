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

import io.vertx.ext.web.RoutingContext;
import java.text.Normalizer;
import java.text.Normalizer.Form;
import java.util.regex.Pattern;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.apache.commons.lang3.StringUtils;

/**
 * Various useful validation functions.
 *
 * @author garricko
 */
public class Valid {
  private static final Pattern ALPHANUMERIC_4K = Pattern.compile("[a-zA-Z0-9]{1,4000}");
  private static final Pattern NUMBER_4K = Pattern.compile("[0-9]{1,4000}");

  // Maybe I could annotate this somehow like @DoNotModify (unsafe to do things like lowercase or normalize after validation)
  @Nullable
  public static String matchesOpt(String value, Pattern requiredPattern, String validationMessage) {
    if (value == null || value.length() == 0) {
      return null;
    }

    // Eliminate potentially malicious crafted Unicode escape sequences
    value = Normalizer.normalize(value, Form.NFKC);

    if (requiredPattern.matcher(value).matches()) {
      return value;
    }

    throw new BadRequestException(validationMessage);
  }

  @Nonnull
  public static boolean isFalse(Boolean value,  String validationMessage) {

    if ( value == null || value != false) {
      throw new BadRequestException(validationMessage);
    }

    return true;
  }

  @Nonnull
  public static boolean isTrue(Boolean value,  String validationMessage) {

    if (value == null || value != true) {
      throw new BadRequestException(validationMessage);
    }

    return true;
  }

  @Nonnull
  public static void alphaSpaceMaxLength(String value, Integer maxLength, String validationMessage) {

    if ((value == null) ||(value.length() >  maxLength ) || !(StringUtils.isAlphaSpace(value))) {
      throw new BadRequestException(validationMessage);
    }

  }

  @Nonnull
  public static String matchesReq(String value, Pattern requiredPattern, String validationMessage) {
    value = matchesOpt(value, requiredPattern, validationMessage);
    if (value == null) {
      throw new BadRequestException(validationMessage);
    }

    return value;
  }

  @Nonnull
  public static <T> T nonNull(T object, String validationMessage) {
    if (object == null) {
      throw new BadRequestException(validationMessage);
    }

    return object;
  }

  @Nonnull
  public static <T> T useDefault(@Nullable T value, @Nonnull T defaultValue) {
    if (value == null) {
      return defaultValue;
    }

    return value;
  }

  public static Long parseLong(String value, String validationMessage) {
    if (value == null || value.length() == 0) {
      return null;
    }
    try {
      return Long.parseLong(value);
    } catch (NumberFormatException e) {
      throw new BadRequestException(validationMessage);
    }
  }

  @Nonnull
  public static String nonNullNormalized(String value, String validationMessage) {
    if (value == null) {
      throw new BadRequestException(validationMessage);
    }

    // Eliminate potentially malicious crafted Unicode escape sequences
    value = Normalizer.normalize(value, Form.NFKC);

    return value;
  }

  @Nonnull
  public static String safeReq(String value, String validationMessage) {
    return matchesReq(value, ALPHANUMERIC_4K, validationMessage);
  }

  @Nonnull
  public static String safeReq(StringLookup lookup, String key, String validationMessage) {
    return matchesReq(lookup.get(key), ALPHANUMERIC_4K, validationMessage);
  }

  @Nullable
  public static Long nonnegativeLongOpt(String value, String validationMessage) {
    return parseLong(matchesOpt(value, NUMBER_4K, validationMessage), validationMessage);
  }

  public static long nonnegativeLongReq(String value, long defaultValue, String validationMessage) {
    return useDefault(nonnegativeLongOpt(value, validationMessage), defaultValue);
  }

  @Nullable
  public static String formAttributeMatchesOpt(RoutingContext rc, String attributeName, Pattern requiredPattern,
                                               String validationMessage) {
    String value = rc.request().getFormAttribute(attributeName);

    return matchesOpt(value, requiredPattern, validationMessage);
  }

  @Nullable
  public static String formAttributeMatchesOpt(RoutingContext rc, String attributeName, Pattern requiredPattern) {
    return formAttributeMatchesOpt(rc, attributeName, requiredPattern, "Form attribute " + attributeName
        + " must match pattern '" + requiredPattern + "'");
  }

  @Nonnull
  public static String formAttributeMatchesReq(RoutingContext rc, String attributeName, Pattern requiredPattern,
                                               String validationMessage) {
    String value = formAttributeMatchesOpt(rc, attributeName, requiredPattern, validationMessage);

    if (value != null) {
      return value;
    }

    throw new BadRequestException(validationMessage);
  }

  @Nonnull
  public static String formAttributeMatchesReq(RoutingContext rc, String attributeName, Pattern requiredPattern) {
    return formAttributeMatchesReq(rc, attributeName, requiredPattern, "Form attribute " + attributeName
        + " must match pattern '" + requiredPattern + "'");
  }

  @Nonnull
  public static String safeFormAttributeReq(RoutingContext rc, String attributeName, String validationMessage) {
    return formAttributeMatchesReq(rc, attributeName, ALPHANUMERIC_4K, validationMessage);
  }

  @Nonnull
  public static String safeFormAttributeReq(RoutingContext rc, String attributeName) {
    return formAttributeMatchesReq(rc, attributeName, ALPHANUMERIC_4K);
  }

  @Nonnull
  public static String formAttributeEqualsHide(RoutingContext rc, String attributeName, String requiredValue) {
    return formAttributeEquals(rc, attributeName, requiredValue, "Form attribute " + attributeName
        + " does not have the expected value");
  }

  @Nonnull
  public static String formAttributeEqualsShow(RoutingContext rc, String attributeName, String requiredValue) {
    return formAttributeEquals(rc, attributeName, requiredValue, "Form attribute " + attributeName
        + " must have the value '" + requiredValue + "'");
  }

  @Nonnull
  public static String formAttributeEquals(RoutingContext rc, String attributeName, String requiredValue,
                                           String validationMessage) {
    String value = rc.request().getFormAttribute(attributeName);

    if (value == null || !value.equals(requiredValue)) {
      throw new BadRequestException(validationMessage);
    }

    return requiredValue;
  }

  public interface StringLookup {
    String get(String key);
  }
}
