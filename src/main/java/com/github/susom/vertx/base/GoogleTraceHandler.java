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

import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;
import org.slf4j.MDC;

/**
 * Vert.x handler that extracts Google Cloud trace and span IDs from the
 * {@code X-Cloud-Trace-Context} request header and populates SLF4J MDC
 * so that structured log lines emitted during request handling include
 * trace correlation data.
 *
 * <p>The handler also cleans up the MDC keys when the response completes.
 */
public class GoogleTraceHandler implements Handler<RoutingContext> {
  static final String MDC_TRACE_KEY = "logging.googleapis.com/trace";
  static final String MDC_SPAN_KEY  = "logging.googleapis.com/spanId";

  private final String projectId;

  /**
   * Creates a new handler that will format trace IDs using the given GCP project ID.
   *
   * @param projectId GCP project ID (may be null); when non-empty the trace is formatted as
   *                  {@code projects/PROJECT/traces/TRACE_ID}
   */
  public GoogleTraceHandler(String projectId) {
    this.projectId = projectId;
  }

  @Override
  public void handle(RoutingContext ctx) {
    clearTraceContext();
    applyTraceContext(ctx.request().getHeader("X-Cloud-Trace-Context"), projectId);
    ctx.response().endHandler(v -> clearTraceContext());
    ctx.next();
  }

  /**
   * Parses the {@code X-Cloud-Trace-Context} header and writes the trace resource name and span
   * ID into SLF4J MDC so that every log line emitted during the request carries trace correlation
   * data.
   *
   * <p>Header format: {@code TRACE_ID[/SPAN_ID[;o=TRACE_FLAG]]}
   *
   * @param traceHeader value of the {@code X-Cloud-Trace-Context} request header (may be null)
   * @param projectId   GCP project ID (may be null); when non-empty the trace is formatted as
   *                    {@code projects/PROJECT/traces/TRACE_ID}
   */
  static void applyTraceContext(String traceHeader, String projectId) {
    if (traceHeader == null || traceHeader.isEmpty()) {
      clearTraceContext();
      return;
    }
    String[] traceAndFlag = traceHeader.split(";", 2);
    String tracePart = traceAndFlag[0];
    if (tracePart.isEmpty()) {
      clearTraceContext();
      return;
    }
    // Header format: TRACE_ID[/SPAN_ID]
    String[] parts = tracePart.split("/", 2);
    String traceId = parts[0];
    if (traceId.isEmpty()) {
      clearTraceContext();
      return;
    }
    String traceResource = (projectId != null && !projectId.isEmpty())
        ? "projects/" + projectId + "/traces/" + traceId
        : traceId;
    MDC.put(MDC_TRACE_KEY, traceResource);
    if (parts.length >= 2 && !parts[1].isEmpty()) {
      MDC.put(MDC_SPAN_KEY, parts[1]);
    } else {
      MDC.remove(MDC_SPAN_KEY);
    }
  }

  private static void clearTraceContext() {
    MDC.remove(MDC_TRACE_KEY);
    MDC.remove(MDC_SPAN_KEY);
  }
}
