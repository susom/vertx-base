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

  public MetricsHandler(SecureRandom secureRandom) {
    this(secureRandom, false);
  }

  public MetricsHandler(SecureRandom secureRandom, boolean dumpRequest) {
    this.requestIdPrefix = new TokenGenerator(secureRandom).create(5);
    this.dumpRequest = dumpRequest;
  }

  /**
   * Get the Metric object for the specified routing context, creating it
   * if it does not already exist. This gets called automatically by this
   * handler. It is mainly intended for situations where you might have a
   * handler sitting in front of this one (e.g. for authentication), and
   * you want to make sure the metrics object is available and starts its
   * timer before you do anything.
   */
  @Nonnull
  public static Metric metricFor(@Nonnull RoutingContext rc) {
    Metric metric = rc.get("metric");
    if (metric == null) {
      metric = new Metric(log.isDebugEnabled());
      rc.put("metric", metric);
    }
    return metric;
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
    if (query != null && query.length() > 0) {
      log.debug("Received " + rc.request().method() + " " + rc.request().path() + "?" + query);
    } else {
      log.debug("Received " + rc.request().method() + " " + rc.request().path());
    }
    log.debug("X-Forwarded-For: " + rc.request().getHeader("X-Forwarded-For"));
    log.debug("User-Agent: " + rc.request().getHeader("User-Agent"));
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
            if (body.containsKey("password"))
              body.put("password", "xxx");
            buf.append("\nBody: ").append(body.encodePrettily());
          }
        }
        log.debug(buf.toString());
      }
      MDC.clear();
    });
    rc.next();
  }
}
