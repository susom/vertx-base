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
    applyTraceContext(ctx.request().getHeader("X-Cloud-Trace-Context"), projectId);
    ctx.response().endHandler(v -> {
      MDC.remove(MDC_TRACE_KEY);
      MDC.remove(MDC_SPAN_KEY);
    });
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
      return;
    }
    // Header format: TRACE_ID/SPAN_ID;o=TRACE_FLAG
    String[] parts = traceHeader.split("[/;]", 3);
    String traceId = parts[0];
    String traceResource = (projectId != null && !projectId.isEmpty())
        ? "projects/" + projectId + "/traces/" + traceId
        : traceId;
    MDC.put(MDC_TRACE_KEY, traceResource);
    if (parts.length >= 2 && !parts[1].isEmpty()) {
      MDC.put(MDC_SPAN_KEY, parts[1]);
    }
  }
}
