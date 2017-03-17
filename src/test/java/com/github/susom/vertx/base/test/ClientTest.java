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
package com.github.susom.vertx.base.test;

import com.github.susom.vertx.base.VertxBase;
import io.vertx.core.Vertx;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

/**
 * Verify the SLF4J MDC is preserved during HTTP client calls.
 *
 * @author garricko
 */
@RunWith(VertxUnitRunner.class)
public class ClientTest {
  private static final Logger log = LoggerFactory.getLogger(ClientTest.class);

  /**
   * Make sure we can use the HttpClient in a way that preserves MDC context.
   */
  @Test
  public void testMdc(TestContext context) {
    Async async = context.async();

    Vertx vertx = Vertx.vertx();
    vertx.createHttpServer().requestHandler(r -> r.response().end("Hello"))
        .listen(8101, server -> {
          MDC.put("foo", "bar");
          log.debug("Server up: {}", Vertx.currentContext());
          vertx.createHttpClient().get(8101, "localhost", "/foo").handler(VertxBase.mdc(response -> {
            log.debug("Client got response: {}", Vertx.currentContext());
            context.assertEquals("bar", MDC.get("foo"));
            response.bodyHandler(VertxBase.mdc(body -> {
              log.debug("Client got body: {}", Vertx.currentContext());
              context.assertEquals("bar", MDC.get("foo"));
              vertx.close(closed -> async.complete());
            }));
          })).end();
          MDC.clear();
    });
  }
}
