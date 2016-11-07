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
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;

/**
 * Simple body handler that enforces a size limit (16k by default)
 * and prohibits file uploads.
 *
 * @author garricko
 */
public class StrictBodyHandler implements Handler<RoutingContext> {
  private final long bodyLimitBytes;
  private boolean multipart;
  private boolean mergeFormAttributes;

  /**
   * Use a body size limit of 16,000 bytes.
   */
  public StrictBodyHandler() {
    this(16000);
  }

  /**
   * Use the specified body size limit (-1 means unlimited).
   */
  public StrictBodyHandler(long bodyLimitBytes) {
    this.bodyLimitBytes = bodyLimitBytes;
  }

  /**
   * Indicate this request will contain a multi-part body (e.g. encoded HTML form). This
   * will ensure {@link io.vertx.core.http.HttpServerRequest#setExpectMultipart(boolean)}
   * is called before we read the body.
   */
  public StrictBodyHandler multipart() {
    multipart = true;
    return this;
  }

  /**
   * Indicate this request will contain a multi-part body (e.g. encoded HTML form). In
   * addition, form attributes will be treated like (combined with) query parameters.
   */
  public StrictBodyHandler multipartMergeForm() {
    mergeFormAttributes = true;
    return multipart();
  }

  public void handle(RoutingContext rc) {
    if (multipart) {
      rc.request().setExpectMultipart(true);
    }

    Buffer body = Buffer.buffer();
    boolean[] failed = { false };

    rc.request().handler(buf -> {
      if (failed[0]) {
        return;
      }
      if (bodyLimitBytes != -1 && (body.length() + buf.length()) > bodyLimitBytes) {
        failed[0] = true;
        rc.fail(413);
      } else {
        body.appendBuffer(buf);
      }
    }).endHandler(v -> {
      Metric metric = rc.get("metric");
      if (failed[0]) {
        if (metric != null) {
          metric.checkpoint("bodyTooBig");
        }
        return;
      }
      if (metric != null) {
        metric.checkpoint("body[" + body.length() + "]");
      }

      // Treat the form like query parameters if requested
      HttpServerRequest request = rc.request();
      if (mergeFormAttributes) {
        request.params().addAll(request.formAttributes());
      }

      rc.setBody(body);
      rc.next();
    }).exceptionHandler(rc::fail);
  }
}
