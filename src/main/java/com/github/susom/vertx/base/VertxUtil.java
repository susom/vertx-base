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

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import java.util.Map;
import org.slf4j.MDC;

/**
 * This is a convenience class to work-around issues with using the SLF4J
 * MDC class. It provides versions of async functionality that preserve
 * the MDC across the event and worker threads.
 *
 * @author garricko
 */
public class VertxUtil {
  /**
   * Wrap a Handler in a way that will preserve the SLF4J MDC context.
   * The context from the current thread at the time of this method call
   * will be cached and restored within the wrapper at the time the
   * handler is invoked.
   */
  public static <T> Handler<T> mdc(Handler<T> handler) {
    Map mdc = MDC.getCopyOfContextMap();

    return t -> {
      try {
        if (mdc != null) {
          MDC.setContextMap(mdc);
        }
        handler.handle(t);
      } finally {
        MDC.clear();
      }
    };
  }

  /**
   * Equivalent to {@link Vertx#executeBlocking(Handler, Handler)},
   * but preserves the {@link MDC} correctly.
   */
  public static <T> void executeBlocking(Vertx vertx, Handler<Future<T>> future, Handler<AsyncResult<T>> handler) {
    executeBlocking(vertx, future, true, handler);
  }

  /**
   * Equivalent to {@link Vertx#executeBlocking(Handler, boolean, Handler)},
   * but preserves the {@link MDC} correctly.
   */
  public static <T> void executeBlocking(Vertx vertx, Handler<Future<T>> future, boolean ordered,
                                         Handler<AsyncResult<T>> handler) {
    vertx.executeBlocking(mdc(future), ordered, mdc(handler));
  }
}
