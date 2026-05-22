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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.classic.spi.StackTraceElementProxy;
import ch.qos.logback.core.encoder.EncoderBase;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;

/**
 * Logback encoder that outputs log events as newline-delimited JSON compatible with
 * Google Cloud Logging (Cloud Run).
 *
 * <p>GCP-specific fields produced:
 * <ul>
 *   <li>{@code severity} – GCP severity string mapped from the Logback level</li>
 *   <li>{@code message}  – The formatted log message</li>
 *   <li>{@code time}     – RFC 3339 / ISO-8601 timestamp</li>
 *   <li>{@code logging.googleapis.com/trace} – Cloud trace resource name (when present in MDC)</li>
 *   <li>{@code logging.googleapis.com/spanId} – Span ID (when present in MDC)</li>
 *   <li>{@code logging.googleapis.com/labels/userId} – User ID (when present in MDC)</li>
 * </ul>
 *
 * <p>Enable structured logging by configuring your Logback appender to use this
 * encoder class. The trace/span MDC keys are populated automatically by
 * {@link GoogleTraceHandler} from the {@code X-Cloud-Trace-Context} request header.
 */
public class GoogleStructuredLogging extends EncoderBase<ILoggingEvent> {

  static final String MDC_USER_ID_KEY = "userId";

  @Override
  public byte[] headerBytes() {
    return new byte[0];
  }

  @Override
  public byte[] footerBytes() {
    return new byte[0];
  }

  @Override
  public byte[] encode(ILoggingEvent event) {
    StringBuilder sb = new StringBuilder(256);
    sb.append('{');

    appendStringField(sb, "time", Instant.ofEpochMilli(event.getTimeStamp()).toString());
    sb.append(',');
    appendStringField(sb, "severity", toGcpSeverity(event.getLevel()));
    sb.append(',');
    appendStringField(sb, "message", event.getFormattedMessage());
    sb.append(',');
    appendStringField(sb, "logger", event.getLoggerName());
    sb.append(',');
    appendStringField(sb, "thread", event.getThreadName());

    Map<String, String> mdc = event.getMDCPropertyMap();
    if (mdc != null) {
      String trace = mdc.get(GoogleTraceHandler.MDC_TRACE_KEY);
      if (trace != null) {
        sb.append(',');
        appendStringField(sb, GoogleTraceHandler.MDC_TRACE_KEY, trace);
      }
      String span = mdc.get(GoogleTraceHandler.MDC_SPAN_KEY);
      if (span != null) {
        sb.append(',');
        appendStringField(sb, GoogleTraceHandler.MDC_SPAN_KEY, span);
      }
      String userId = mdc.get(MDC_USER_ID_KEY);
      if (userId != null) {
        sb.append(',');
        appendStringField(sb, "logging.googleapis.com/labels/userId", userId);
      }
    }

    IThrowableProxy throwable = event.getThrowableProxy();
    if (throwable != null) {
      sb.append(',');
      appendStringField(sb, "error", formatThrowable(throwable));
    }

    sb.append('}');
    sb.append('\n');
    return sb.toString().getBytes(StandardCharsets.UTF_8);
  }

  // ── helpers ────────────────────────────────────────────────────────────────

  private static String toGcpSeverity(Level level) {
    if (level == Level.ERROR) return "ERROR";
    if (level == Level.WARN)  return "WARNING";
    if (level == Level.INFO)  return "INFO";
    if (level == Level.DEBUG) return "DEBUG";
    if (level == Level.TRACE) return "DEBUG";
    return "DEFAULT";
  }

  private static void appendStringField(StringBuilder sb, String key, String value) {
    sb.append('"');
    appendEscaped(sb, key);
    sb.append("\":\"");
    appendEscaped(sb, value);
    sb.append('"');
  }

  private static void appendEscaped(StringBuilder sb, String text) {
    if (text == null) {
      return;
    }
    for (int i = 0; i < text.length(); i++) {
      char c = text.charAt(i);
      switch (c) {
        case '"':  sb.append("\\\""); break;
        case '\\': sb.append("\\\\"); break;
        case '\b': sb.append("\\b");  break;
        case '\f': sb.append("\\f");  break;
        case '\n': sb.append("\\n");  break;
        case '\r': sb.append("\\r");  break;
        case '\t': sb.append("\\t");  break;
        default:
          if (c < 0x20) {
            sb.append(String.format("\\u%04x", (int) c));
          } else {
            sb.append(c);
          }
      }
    }
  }

  private static String formatThrowable(IThrowableProxy t) {
    StringBuilder sb = new StringBuilder();
    sb.append(t.getClassName());
    if (t.getMessage() != null) {
      sb.append(": ").append(t.getMessage());
    }
    for (StackTraceElementProxy ste : t.getStackTraceElementProxyArray()) {
      sb.append('\n').append('\t').append("at ").append(ste.getSTEAsString());
    }
    if (t.getCause() != null) {
      sb.append('\n').append("Caused by: ").append(formatThrowable(t.getCause()));
    }
    return sb.toString();
  }
}
