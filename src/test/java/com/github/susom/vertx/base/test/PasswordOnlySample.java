/*
 * Copyright 2022 The Board of Trustees of The Leland Stanford Junior University.
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

import com.github.susom.database.Config;
import com.github.susom.vertx.base.AuthenticatedUser;
import com.github.susom.vertx.base.PasswordOnlyAuthenticator;
import com.github.susom.vertx.base.PasswordOnlyValidator;
import com.github.susom.vertx.base.Security;
import com.github.susom.vertx.base.StrictResourceHandler;
import com.github.susom.vertx.base.Valid;
import com.github.susom.vertx.base.VertxBase;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.github.susom.vertx.base.VertxBase.*;

/**
 * Sample application for manual testing and experimentation.
 */
public class PasswordOnlySample {
  private static final Logger log = LoggerFactory.getLogger(PasswordOnlySample.class);

  public static void main(String[] args) {
    try {
      initializeLogging();
      redirectConsoleToLog();
      Vertx vertx = Vertx.vertx();
      SecureRandom random = createSecureRandom(vertx);

      int port = 8877;
      Config config = Config.from()
//          .value("insecure.log.full.requests", "yes")
          .value("listen.url", "http://localhost:" + port)
          .value("public.url", "http://localhost:" + port)
          // This secret is used for siging the JWT session token
          .value("passwordonly.jwt.secret", "lskdjfoiweyriugo389yru")
          .value("passwordonly.sesssion.timeout.minutes", "1")
          // If you want to customize the login screen
          .value("passwordonly.message.header", "Guess a color.")
          .value("passwordonly.message.label", "Color:")
          .value("passwordonly.message.placeholder", "Something pretty")
          .value("passwordonly.message.footer", "Brought to you by rainbows.")
          .get();

      Router root = rootRouter(vertx, "/app");
      PasswordOnlyValidator validator = password -> {
        if ("testy".equals(password)) {
          Set<String> authority = new HashSet<>();
          authority.add("service:secret");
          authority.add("service:secret:message:1000");
          authority.add("service:secret:message:1001");
          return new AuthenticatedUser("testy", "boo", "Testy Testerson", authority);
        }
        return null;
      };
      Security security = new PasswordOnlyAuthenticator(vertx, root, random, validator, config);

      // A static website with public and private content
      root.get("/public/readme").handler(rc -> rc.response().sendFile("README.md"));
      Router priv = security.authenticatedRouter("/private");
      priv.get("/pom").handler(rc -> rc.response().sendFile("pom.xml"));

      // A dynamic web application with API calls
      Router sub = security.authenticatedRouter("/app");
      sub.get("/api/v1/secret").handler(security.requireAuthority("service:secret"));
      sub.get("/api/v1/secret").handler(rc -> {
        Long messageId = Valid.nonnegativeLongOpt(rc.request().getParam("id"), "Expecting a number for id");
        if (messageId == null) {
          rc.response().end(new JsonObject().put("message", "Hi").encode());
        } else {
          AuthenticatedUser.required(rc).isAuthorized("service:secret:message:" + messageId, r -> {
            if (r.succeeded() && r.result()) {
              rc.response().end(new JsonObject().put("message", "Hi " + messageId).encode());
            } else {
              rc.response().end(new JsonObject().put("message", "Oops, can't access that one").encode());
            }
          });
        }
      }).failureHandler(VertxBase::jsonApiFail);
      sub.get("/*").handler(new StrictResourceHandler(vertx)
              .addDir("static/sample")
              .rootIndex("sample.nocache.html")
              .warnIfNotFound());

      // Start the server
      vertx.createHttpServer().requestHandler(root).listen(port, "localhost", h -> {
        if (h.succeeded()) {
          int actualPort = h.result().actualPort();
          log.info("Started server on port " + actualPort + ":\n" +
              "    http://localhost:" + actualPort + "/app\n" +
              "    http://localhost:" + actualPort + "/app?a=b#c\n" +
              "    http://localhost:" + actualPort + "/public/readme\n" +
              "    http://localhost:" + actualPort + "/private/pom\n" +
              "    http://localhost:" + actualPort + "/private/pom?a=b#c\n");
        } else {
          log.error("Could not start server", h.cause());
        }
      });
    } catch (Exception e) {
      log.error("Unexpected exception in main()", e);
      System.exit(1);
    }
  }
}
