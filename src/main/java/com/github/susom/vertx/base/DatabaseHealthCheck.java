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

import com.github.susom.database.Config;
import com.github.susom.database.DatabaseException;
import com.github.susom.database.DatabaseProviderVertx.Builder;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpHeaders;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

/**
 * A simple health check and status pages that determine status based
 * on connecting to the database.
 *
 * @author garricko
 */
public class DatabaseHealthCheck {
  private static final Logger log = LoggerFactory.getLogger(DatabaseHealthCheck.class);
  private final int intervalSeconds;
  private Instant statusTime = Instant.now();
  private int statusCode = 200;
  private String statusMessage = "{\n  \"status\": \"WARNING\",\n  \"message\": "
      + "\"Waiting for status check to start\",\n  \"lastRefresh\": \""
      + DateTimeFormatter.ISO_INSTANT.format(statusTime) + "\"\n}\n";

  public DatabaseHealthCheck(Vertx vertx, Builder db, Config config) {
    this(vertx, db, config.getInteger("healthcheck.interval.seconds", 60));
  }

  public DatabaseHealthCheck(Vertx vertx, Builder db, int intervalSeconds) {
    this.intervalSeconds = intervalSeconds;
    if (intervalSeconds > 0) {
      // DCS status per https://medwiki.stanford.edu/display/apps/Status+Page+Policy+and+Standards
      Handler<Long> statusCheck = h -> {
        MDC.clear();
        MDC.put("userId", "<health-check>");
        db.transactAsync(dbs -> {
          return dbs.get().toSelect("select ?" + dbs.get().flavor().fromAny())
              .argDateNowPerDb().queryFirstOrNull(r -> {
                Date appDate = dbs.get().nowPerApp();
                Date dbDate = r.getDateOrNull();

                if (dbDate == null) {
                  throw new DatabaseException("Expecting a date in the result");
                }

                if (Math.abs(appDate.getTime() - dbDate.getTime()) > 3600000) {
                  throw new DatabaseException("App and db time are over an hour apart (check your timezones) app: "
                      + DateTimeFormatter.ISO_INSTANT.format(appDate.toInstant()) + " db: "
                      + DateTimeFormatter.ISO_INSTANT.format(dbDate.toInstant()));
                }

                if (Math.abs(appDate.getTime() - dbDate.getTime()) > 30000) {
                  throw new DatabaseException("App and db time are over thirty seconds apart (check your clocks) app: "
                      + DateTimeFormatter.ISO_INSTANT.format(appDate.toInstant()) + " db: "
                      + DateTimeFormatter.ISO_INSTANT.format(dbDate.toInstant()));
                }

                return null;
              });
        }, result -> {
          statusTime = Instant.now();
          if (result.succeeded()) {
            statusCode = 200;
            statusMessage = "{\n  \"status\": \"OK\",\n  \"message\": \"OVERALL STATUS: OK\",\n  \"lastRefresh\": \""
                + DateTimeFormatter.ISO_INSTANT.format(statusTime) + "\"\n}\n";
          } else {
            statusCode = 500;
            statusMessage = "{\n  \"status\": \"ERROR\",\n  \"message\": \"Cannot connect to database\",\n  "
                + "\"lastRefresh\": \"" + DateTimeFormatter.ISO_INSTANT.format(statusTime) + "\"\n}\n";
            log.error("Problem with the database health check: " + innermostMessage(result.cause()), result.cause());
          }
        });
        MDC.clear();
      };
      vertx.runOnContext(h -> statusCheck.handle(vertx.setPeriodic(intervalSeconds * 1000, statusCheck)));
    }
  }

  public void addStatusHandlers(Router root) {
    if (intervalSeconds > 0) {
      // DCS status per https://medwiki.stanford.edu/display/apps/Status+Page+Policy+and+Standards
      Handler<RoutingContext> handler = rc -> {
        if (statusTime.isBefore(Instant.now().minus(5, ChronoUnit.MINUTES))) {
          rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
              .setStatusCode(500).end("{\n  \"status\": \"ERROR\",\n  \"message\": \"Status check is "
              + "hung\",\n  \"lastRefresh\": \"" + DateTimeFormatter.ISO_INSTANT.format(statusTime) + "\"\n}\n");
        } else {
          rc.response().putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
              .setStatusCode(statusCode).end(statusMessage);
        }
      };
      root.get("/status").handler(handler);
      root.get("/status/app").handler(handler);
    }
  }

  private String innermostMessage(Throwable t) {
    if (t == null) {
      return "";
    }
    Throwable innermost = t;
    while (innermost.getCause() != null) {
      innermost = innermost.getCause();
    }
    return innermost.getMessage();
  }
}
