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

import com.github.susom.database.Config;
import com.github.susom.database.DatabaseProviderVertx;
import com.github.susom.database.DatabaseProviderVertx.Builder;
import com.github.susom.dbgoodies.vertx.DatabaseHealthCheck;
import com.github.susom.vertx.base.AuthenticatedUser;
import com.github.susom.vertx.base.SecurityImpl;
import com.github.susom.vertx.base.StrictResourceHandler;
import com.github.susom.vertx.base.Valid;
import com.github.susom.vertx.base.VertxBase;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import java.io.FilePermission;
import java.net.SocketPermission;
import java.security.SecureRandom;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.github.susom.vertx.base.VertxBase.*;

/**
 * Sample application for manual testing and experimentation.
 */
public class SampleMain {
  private static final Logger log = LoggerFactory.getLogger(SampleMain.class);

  public static void main(String[] args) {
    try {
      initializeLogging();
      redirectConsoleToLog();
      startSecurityManager(
          // For serving our content
          new SocketPermission("localhost:8080", "listen,resolve"),
          // For connecting to the fake security server (embedded)
          new SocketPermission("localhost:8080", "connect,resolve"),
          // These two are for hsqldb to store its database files
          new FilePermission(workDir() + "/target", "read,write,delete"),
          new FilePermission(workDir() + "/target/-", "read,write,delete")
      );

      Config config = Config.from()
          .value("database.url", "jdbc:hsqldb:file:target/hsqldb;shutdown=true")
          .value("database.user", "SA")
          .value("database.password", "")
          .value("listen.url", "http://localhost:8080")
          .value("public.url", "http://localhost:8080")
          .value("insecure.fake.security", "yes").get();
//      String propertiesFile = System.getProperty("properties", "local.properties");
//      Config config = Config.from().systemProperties().propertyFile(propertiesFile.split(":")).get();

      Vertx vertx = Vertx.vertx();
      SecureRandom random = createSecureRandom(vertx);
      Builder db = DatabaseProviderVertx.pooledBuilder(vertx, config).withSqlParameterLogging();

      // The meat of the application goes here
      Router root = rootRouter(vertx, "/app");
      SecurityImpl security = new SecurityImpl(vertx, root, random, config::getString);
      Router sub = authenticatedRouter(vertx, random, security, false);
      root.mountSubRouter("/app", sub);
      sub.get("/api/v1/secret").handler(security.requireAuthority("service:secret"));
      sub.get("/api/v1/secret").handler(rc -> {
        Long messageId = Valid.nonnegativeLongOpt(rc.request().getParam("id"), "Expecting a number for id");
        if (messageId == null) {
          rc.response().end(new JsonObject().put("message", "Hi").encode());
        } else {
          AuthenticatedUser.required(rc).isAuthorised("service:secret:message:" + messageId, r -> {
            if (r.succeeded() && r.result()) {
              rc.response().end(new JsonObject().put("message", "Hi " + messageId).encode());
            } else {
              rc.response().end(new JsonObject().put("message", "Oops, can't access that one").encode());
            }
          });
        }
      }).failureHandler(VertxBase::jsonApiFail);

      sub.get("/hello").handler(rc -> rc.response().setStatusCode(503).sendFile("static/errors/503.html"));

      // Static content coming from the Java classpath. This is last in this
      // method because the routing path overlaps with the others above, and
      // we want them to take precedence.
      sub.get("/*").handler(new StrictResourceHandler(vertx)
              .addDir("static/sample")
              .addDir("static/assets", "**/*", "assets")
              .rootIndex("sample.nocache.html"));

      // Add status pages per DCS standards (JSON returned from /status and /status/app)
      new DatabaseHealthCheck(vertx, db, config).addStatusHandlers(root);

      // Start the server
      vertx.createHttpServer().requestHandler(root::accept).listen(8080, result ->
          log.info("Started server on port " + 8080 + ":\n    http://localhost:8080/app/")
      );

      // Make sure we cleanly shutdown Vert.x and the database pool
      addShutdownHook(vertx, db::close);
    } catch (Exception e) {
      log.error("Unexpected exception in main()", e);
      System.exit(1);
    }
  }
}
