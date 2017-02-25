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
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.annotation.Nonnull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

/**
 * Simple body handler that enforces a size limit (16k by default)
 * and prohibits file uploads.
 *
 * @author garricko
 */
public class MetricsHandler implements Handler<RoutingContext> {
  private static final Logger log = LoggerFactory.getLogger(MetricsHandler.class);
  private final boolean dumpRequest;
  private final String requestIdPrefix;
  private long requestId = 1;
  private List<String> headersToLog = new ArrayList<>();

  public MetricsHandler(SecureRandom secureRandom) {
    this(secureRandom, false);
  }

  public MetricsHandler(SecureRandom secureRandom, boolean dumpRequest) {
    this.requestIdPrefix = new TokenGenerator(secureRandom).create(5);
    this.dumpRequest = dumpRequest;
  }

  public MetricsHandler logHeaders(String... headers) {
    headersToLog.addAll(Arrays.asList(headers));
    return this;
  }

  public MetricsHandler logXForwardedFor() {
    headersToLog.add("X-Forwarded-For");
    return this;
  }

  public MetricsHandler logUserAgent() {
    headersToLog.add("User-Agent");
    return this;
  }

  /**
   * Get the Metric object for the specified routing context, creating it
   * if it does not already exist. This gets called automatically by this
   * handler. It is mainly intended for situations where you might have a
   * handler sitting in front of this one (e.g. for authentication), and
   * you want to make sure the metrics object is available and starts its
   * timer before you do anything.
   *
   * @deprecated use checkpoint() instead because Metric is shaded by this library
   */
  @Nonnull @Deprecated
  public static Metric metricFor(@Nonnull RoutingContext rc) {
    Metric metric = rc.get("metric");
    if (metric == null) {
      metric = new Metric(log.isDebugEnabled());
      rc.put("metric", metric);
    }
    return metric;
  }

  public static void checkpoint(@Nonnull RoutingContext rc, String label) {
    Metric metric = rc.get("metric");
    if (metric == null) {
      metric = new Metric(log.isDebugEnabled());
      rc.put("metric", metric);
    }
    metric.checkpoint(label);
  }

  public void handle(RoutingContext rc) {
    String externalRequestId = rc.request().getHeader("X-REQUEST-ID");
    if (externalRequestId == null || !externalRequestId.matches("[a-zA-Z0-9:]{1,80}")) {
      externalRequestId = "";
    } else {
      externalRequestId = ":" + externalRequestId;
    }
    MDC.put("requestId", requestIdPrefix + Long.toString(requestId++, Character.MAX_RADIX) + externalRequestId);
    Metric metric = metricFor(rc);
    String query = rc.request().query();
    if (log.isDebugEnabled()) {
      StringBuilder message = new StringBuilder();
      message.append("Received ").append(rc.request().method()).append(" ").append(rc.request().path());
      if (query != null && query.length() > 0) {
        message.append("?").append(query);
      }
      if (headersToLog != null) {
        for (String header : headersToLog) {
          String headerValue = rc.request().getHeader(header);
          if (headerValue != null) {
            message.append("\n    ").append(header).append(": ").append(headerValue);
          }
        }
      }
      log.debug(message.toString());
    }
    rc.response().headersEndHandler(h -> metric.checkpoint("call"));
    rc.addBodyEndHandler(h -> {
      metric.done("send");

      if (log.isDebugEnabled()) {
        StringBuilder buf = new StringBuilder();
        buf.append("Served ").append(rc.response().getStatusCode()).append(": ");
        metric.printMessage(buf);
        buf.append(' ').append(rc.request().path());
        if (dumpRequest) {
          buf.append("\nHeaders: ").append(rc.request().headers().entries());
          String contentType = rc.request().headers().get("Content-Type");
          if (contentType != null && contentType.contains("application/json")) {
            JsonObject body = new JsonObject(rc.getBodyAsString());
            if (body.containsKey("password")) {
              body.put("password", "xxx");
            }
            buf.append("\nBody: ").append(body.encodePrettily());
          }
        }
        log.debug(buf.toString());
      }
    });
    rc.next();
  }
}
