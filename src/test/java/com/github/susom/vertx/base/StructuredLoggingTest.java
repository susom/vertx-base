package com.github.susom.vertx.base;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.LoggingEvent;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.http.HttpMethod;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import io.vertx.ext.web.Router;
import java.nio.charset.StandardCharsets;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

/**
 * Tests for structured logging support:
 *
 * <ul>
 *   <li>GoogleStructuredLogging – structured vs plain-message output, severity mapping, JSON escaping,
 *       trace/span inclusion, throwable formatting</li>
 *   <li>GoogleTraceHandler.applyTraceContext – all X-Cloud-Trace-Context header variants and
 *       GOOGLE_CLOUD_PROJECT formatting</li>
 *   <li>HTTP-level integration (vertx-unit) – the route handler sets/clears MDC correctly for
 *       every combination of header presence</li>
 * </ul>
 */
@RunWith(VertxUnitRunner.class)
public class StructuredLoggingTest {

  // ── shared Vert.x infrastructure ─────────────────────────────────────────

  private Vertx vertx;
  private int port;

  @Before
  public void startServer(TestContext ctx) {
    vertx = Vertx.vertx();
    Router router = Router.router(vertx);

    // Reproduce the exact trace handler from MainVerticle (no project ID for tests).
    router.route().handler(new GoogleTraceHandler(null));

    // Echo endpoint: responds with the MDC values it observes on the event-loop thread.
    router.get("/echo").handler(routingCtx -> {
      String trace = MDC.get(GoogleTraceHandler.MDC_TRACE_KEY);
      String span  = MDC.get(GoogleTraceHandler.MDC_SPAN_KEY);
      routingCtx.response()
          .putHeader("X-Trace-Value", trace != null ? trace : "")
          .putHeader("X-Span-Value",  span  != null ? span  : "")
          .end("ok");
    });

    vertx.createHttpServer()
        .requestHandler(router)
        .listen(0)
        .onComplete(ctx.asyncAssertSuccess(s -> port = s.actualPort()));
  }

  @After
  public void stopServer(TestContext ctx) {
    MDC.clear();
    vertx.close(ctx.asyncAssertSuccess());
  }

  // ══════════════════════════════════════════════════════════════════════════
  // GoogleStructuredLogging – structured output
  // ══════════════════════════════════════════════════════════════════════════

  /** Every log line must contain the five mandatory JSON fields. */
  @Test
  public void testStructuredLoggingRequiredFields() {
    ILoggingEvent event = makeEvent(Level.INFO, "Hello structured world");
    String json = encode(event);

    assertTrue("must have time field",     json.contains("\"time\":\""));
    assertTrue("must have severity field", json.contains("\"severity\":\"INFO\""));
    assertTrue("must have message field",  json.contains("\"message\":\"Hello structured world\""));
    assertTrue("must have logger field",   json.contains("\"logger\":\""));
    assertTrue("must have thread field",   json.contains("\"thread\":\""));
    assertTrue("must end with newline",    json.endsWith("\n"));
    // Must be a valid single-line JSON object
    assertTrue("must start with {", json.trim().startsWith("{"));
    assertTrue("must end with }",   json.trim().endsWith("}"));
  }

  /** Severity levels are mapped to the Google Cloud Logging severity strings. */
  @Test
  public void testSeverityLevelMapping() {
    assertEquals("ERROR",   extractField(encode(makeEvent(Level.ERROR, "e")), "severity"));
    assertEquals("WARNING", extractField(encode(makeEvent(Level.WARN,  "w")), "severity"));
    assertEquals("INFO",    extractField(encode(makeEvent(Level.INFO,  "i")), "severity"));
    assertEquals("DEBUG",   extractField(encode(makeEvent(Level.DEBUG, "d")), "severity"));
    assertEquals("DEBUG",   extractField(encode(makeEvent(Level.TRACE, "t")), "severity"));
  }

  // ══════════════════════════════════════════════════════════════════════════
  // GoogleStructuredLogging – plain-message (no MDC) case
  // ══════════════════════════════════════════════════════════════════════════

  /** When MDC contains no trace info the trace/span fields must be absent. */
  @Test
  public void testRegularLoggingNoTraceFields() {
    MDC.clear();
    ILoggingEvent event = makeEvent(Level.INFO, "Plain message");
    String json = encode(event);

    assertFalse("trace field must be absent",
        json.contains("\"" + GoogleTraceHandler.MDC_TRACE_KEY + "\""));
    assertFalse("span field must be absent",
        json.contains("\"" + GoogleTraceHandler.MDC_SPAN_KEY + "\""));
    assertTrue("message must still be present",
        json.contains("\"message\":\"Plain message\""));
  }

  /** When MDC holds a trace ID the JSON output must include both trace and span fields. */
  @Test
  public void testStructuredLoggingWithTraceAndSpan() {
    MDC.put(GoogleTraceHandler.MDC_TRACE_KEY, "projects/my-project/traces/abc123");
    MDC.put(GoogleTraceHandler.MDC_SPAN_KEY,  "def456");
    ILoggingEvent event = makeEvent(Level.INFO, "Traced message");
    String json = encode(event);

    assertEquals("projects/my-project/traces/abc123",
        extractField(json, GoogleTraceHandler.MDC_TRACE_KEY));
    assertEquals("def456",
        extractField(json, GoogleTraceHandler.MDC_SPAN_KEY));
  }

  /** Trace present but no span – only the trace field should appear. */
  @Test
  public void testStructuredLoggingWithTraceOnly() {
    MDC.put(GoogleTraceHandler.MDC_TRACE_KEY, "traceonly123");
    ILoggingEvent event = makeEvent(Level.DEBUG, "Trace no span");
    String json = encode(event);

    assertEquals("traceonly123", extractField(json, GoogleTraceHandler.MDC_TRACE_KEY));
    assertFalse("span field must be absent when not in MDC",
        json.contains("\"" + GoogleTraceHandler.MDC_SPAN_KEY + "\""));
  }

  /** Special characters in the message body must be properly JSON-escaped. */
  @Test
  public void testJsonEscapingInMessage() {
    ILoggingEvent event = makeEvent(Level.INFO, "Line1\nTab\there \"quoted\" back\\slash");
    String json = encode(event);

    assertTrue("newline must be escaped",    json.contains("\\n"));
    assertTrue("tab must be escaped",        json.contains("\\t"));
    assertTrue("quote must be escaped",      json.contains("\\\""));
    assertTrue("backslash must be escaped",  json.contains("\\\\"));
    // The raw characters must NOT appear unescaped inside the JSON string value
    // (check that newline doesn't appear literally inside the message value boundary)
    assertFalse("raw newline must not appear in JSON",
        json.replaceAll(".*\"message\":\"", "").split("\"")[0].contains("\n"));
  }

  /** When MDC contains a userId the labels field must be present in the JSON output. */
  @Test
  public void testStructuredLoggingWithUserId() {
    MDC.put(GoogleStructuredLogging.MDC_USER_ID_KEY, "user123");
    ILoggingEvent event = makeEvent(Level.INFO, "User action");
    String json = encode(event);

    assertEquals("user123",
        extractField(json, "logging.googleapis.com/labels/userId"));
  }

  /** When MDC contains no userId the labels field must be absent. */
  @Test
  public void testNoUserIdFieldWhenMdcAbsent() {
    MDC.clear();
    ILoggingEvent event = makeEvent(Level.INFO, "No user");
    String json = encode(event);

    assertFalse("userId label field must be absent when not in MDC",
        json.contains("\"logging.googleapis.com/labels/userId\""));
  }

  /** Special characters in the userId value must be properly JSON-escaped. */
  @Test
  public void testUserIdJsonEscaping() {
    MDC.put(GoogleStructuredLogging.MDC_USER_ID_KEY, "user\"with\\special\nchars");
    ILoggingEvent event = makeEvent(Level.INFO, "Escaping test");
    String json = encode(event);

    String extracted = extractField(json, "logging.googleapis.com/labels/userId");
    // extractField returns raw content including escape sequences
    assertEquals("user\\\"with\\\\special\\nchars", extracted);
  }

  /** An attached throwable must appear in an "error" field. */
  @Test
  public void testThrowableIncludedInOutput() {
    Logger logger = (Logger) LoggerFactory.getLogger("test.throwable");
    RuntimeException cause = new RuntimeException("root cause");
    RuntimeException ex = new RuntimeException("outer error", cause);
    LoggingEvent event = new LoggingEvent(
        "fqcn", logger, Level.ERROR, "Something failed", ex, null);
    String json = encode(event);

    assertTrue("error field must be present", json.contains("\"error\":\""));
    assertTrue("exception class must appear", json.contains("RuntimeException"));
    assertTrue("exception message must appear", json.contains("outer error"));
    assertTrue("cause must appear", json.contains("root cause"));
  }

  // ══════════════════════════════════════════════════════════════════════════
  // applyTraceContext – unit tests for all header variants
  // ══════════════════════════════════════════════════════════════════════════

  /** Null header must not populate MDC. */
  @Test
  public void testNullHeaderDoesNotSetMdc() {
    GoogleTraceHandler.applyTraceContext(null, null);

    assertNull("trace must not be set", MDC.get(GoogleTraceHandler.MDC_TRACE_KEY));
    assertNull("span must not be set",  MDC.get(GoogleTraceHandler.MDC_SPAN_KEY));
  }

  /** Empty header must not populate MDC. */
  @Test
  public void testEmptyHeaderDoesNotSetMdc() {
    GoogleTraceHandler.applyTraceContext("", null);

    assertNull("trace must not be set", MDC.get(GoogleTraceHandler.MDC_TRACE_KEY));
    assertNull("span must not be set",  MDC.get(GoogleTraceHandler.MDC_SPAN_KEY));
  }

  /** Header containing only a trace ID (no span, no flag). */
  @Test
  public void testTraceIdOnlyHeader() {
    GoogleTraceHandler.applyTraceContext("abc123", null);

    assertEquals("abc123", MDC.get(GoogleTraceHandler.MDC_TRACE_KEY));
    assertNull("span must not be set", MDC.get(GoogleTraceHandler.MDC_SPAN_KEY));
  }

  /** Header with trace ID and span ID. */
  @Test
  public void testTraceAndSpanHeader() {
    GoogleTraceHandler.applyTraceContext("abc123/def456", null);

    assertEquals("abc123", MDC.get(GoogleTraceHandler.MDC_TRACE_KEY));
    assertEquals("def456", MDC.get(GoogleTraceHandler.MDC_SPAN_KEY));
  }

  /** Full header including the trace flag – flag must be ignored. */
  @Test
  public void testFullHeaderWithFlag() {
    GoogleTraceHandler.applyTraceContext("abc123/def456;o=1", null);

    assertEquals("abc123", MDC.get(GoogleTraceHandler.MDC_TRACE_KEY));
    assertEquals("def456", MDC.get(GoogleTraceHandler.MDC_SPAN_KEY));
  }

  /** Header with trace ID and empty span segment – span must NOT be set. */
  @Test
  public void testTraceWithEmptySpanSegment() {
    GoogleTraceHandler.applyTraceContext("abc123/", null);

    assertEquals("abc123", MDC.get(GoogleTraceHandler.MDC_TRACE_KEY));
    assertNull("span must not be set for empty span segment",
        MDC.get(GoogleTraceHandler.MDC_SPAN_KEY));
  }

  /** When a GCP project ID is provided, the trace is formatted as a resource name. */
  @Test
  public void testTraceWithProjectId() {
    GoogleTraceHandler.applyTraceContext("abc123/def456;o=1", "my-project");

    assertEquals("projects/my-project/traces/abc123",
        MDC.get(GoogleTraceHandler.MDC_TRACE_KEY));
    assertEquals("def456", MDC.get(GoogleTraceHandler.MDC_SPAN_KEY));
  }

  /** An empty project ID falls back to just the trace ID (same as null). */
  @Test
  public void testTraceWithEmptyProjectId() {
    GoogleTraceHandler.applyTraceContext("abc123/def456", "");

    assertEquals("abc123", MDC.get(GoogleTraceHandler.MDC_TRACE_KEY));
  }

  // ══════════════════════════════════════════════════════════════════════════
  // HTTP integration tests (vertx-unit) – MDC set/cleared by the route handler
  // ══════════════════════════════════════════════════════════════════════════

  /** Full X-Cloud-Trace-Context header → both trace and span appear in MDC on the event loop. */
  @Test
  public void testHandlerPopulatesMdcFromFullHeader(TestContext ctx) {
    Async async = ctx.async();
    HttpClient client = vertx.createHttpClient(new HttpClientOptions());

    client.request(HttpMethod.GET, port, "localhost", "/echo")
        .compose(req -> req.putHeader("X-Cloud-Trace-Context", "trace999/span888;o=1").send())
        .onComplete(ctx.asyncAssertSuccess(resp -> {
          ctx.assertEquals("trace999", resp.getHeader("X-Trace-Value"));
          ctx.assertEquals("span888",  resp.getHeader("X-Span-Value"));
          async.complete();
        }));
  }

  /** Trace-ID-only header → trace set, span empty in the response. */
  @Test
  public void testHandlerPopulatesMdcFromTraceOnlyHeader(TestContext ctx) {
    Async async = ctx.async();
    HttpClient client = vertx.createHttpClient(new HttpClientOptions());

    client.request(HttpMethod.GET, port, "localhost", "/echo")
        .compose(req -> req.putHeader("X-Cloud-Trace-Context", "traceonly").send())
        .onComplete(ctx.asyncAssertSuccess(resp -> {
          ctx.assertEquals("traceonly", resp.getHeader("X-Trace-Value"));
          ctx.assertEquals("",          resp.getHeader("X-Span-Value"));
          async.complete();
        }));
  }

  /** No X-Cloud-Trace-Context header → MDC is not populated. */
  @Test
  public void testHandlerWithNoTraceHeader(TestContext ctx) {
    Async async = ctx.async();
    HttpClient client = vertx.createHttpClient(new HttpClientOptions());

    client.request(HttpMethod.GET, port, "localhost", "/echo")
        .compose(HttpClientRequest::send)
        .onComplete(ctx.asyncAssertSuccess(resp -> {
          ctx.assertEquals("", resp.getHeader("X-Trace-Value"));
          ctx.assertEquals("", resp.getHeader("X-Span-Value"));
          async.complete();
        }));
  }

  /** Empty X-Cloud-Trace-Context header value → MDC is not populated. */
  @Test
  public void testHandlerWithEmptyTraceHeader(TestContext ctx) {
    Async async = ctx.async();
    HttpClient client = vertx.createHttpClient(new HttpClientOptions());

    client.request(HttpMethod.GET, port, "localhost", "/echo")
        .compose(req -> req.putHeader("X-Cloud-Trace-Context", "").send())
        .onComplete(ctx.asyncAssertSuccess(resp -> {
          ctx.assertEquals("", resp.getHeader("X-Trace-Value"));
          ctx.assertEquals("", resp.getHeader("X-Span-Value"));
          async.complete();
        }));
  }

  /**
   * Consecutive requests must not bleed MDC state: the second request (no header) must
   * see empty trace/span even after the first request (with header) has completed.
   */
  @Test
  public void testMdcClearedBetweenRequests(TestContext ctx) {
    Async async = ctx.async();
    HttpClient client = vertx.createHttpClient(new HttpClientOptions());

    // First request WITH trace header
    client.request(HttpMethod.GET, port, "localhost", "/echo")
        .compose(req -> req.putHeader("X-Cloud-Trace-Context", "leaky/span;o=1").send())
        .compose(resp -> {
          // Verify the first request populated MDC correctly
          ctx.assertEquals("leaky", resp.getHeader("X-Trace-Value"),
              "First request should have trace value from header");

          // Second request WITHOUT trace header – must not inherit previous MDC
          return client.request(HttpMethod.GET, port, "localhost", "/echo")
              .compose(HttpClientRequest::send);
        })
        .onComplete(ctx.asyncAssertSuccess(resp2 -> {
          ctx.assertEquals("", resp2.getHeader("X-Trace-Value"),
              "MDC must be cleared after response ends");
          ctx.assertEquals("", resp2.getHeader("X-Span-Value"),
              "MDC must be cleared after response ends");
          async.complete();
        }));
  }

  // ── private helpers ───────────────────────────────────────────────────────

  private static ILoggingEvent makeEvent(Level level, String message) {
    Logger logger = (Logger) LoggerFactory.getLogger("com.github.susom.vertx.base.test");
    return new LoggingEvent("fqcn", logger, level, message, null, null);
  }

  private static String encode(ILoggingEvent event) {
    GoogleStructuredLogging encoder = new GoogleStructuredLogging();
    encoder.start();
    return new String(encoder.encode(event), StandardCharsets.UTF_8);
  }

  /**
   * Naive field extractor: returns the value of a JSON string field {@code "key":"VALUE"}.
   * Sufficient for the simple, known-structure JSON our encoder produces.
   */
  private static String extractField(String json, String key) {
    String needle = "\"" + key + "\":\"";
    int start = json.indexOf(needle);
    if (start < 0) return null;
    start += needle.length();
    StringBuilder value = new StringBuilder();
    boolean escape = false;
    for (int i = start; i < json.length(); i++) {
      char c = json.charAt(i);
      if (escape) {
        escape = false;
        value.append('\\').append(c);
        continue;
      }
      if (c == '\\') { escape = true; continue; }
      if (c == '"') break;
      value.append(c);
    }
    return value.toString();
  }
}
