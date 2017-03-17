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
import com.github.susom.database.ConfigMissingException;
import com.github.susom.database.Metric;
import io.vertx.core.AsyncResult;
import io.vertx.core.Context;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import java.io.Closeable;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.AccessControlException;
import java.security.NoSuchAlgorithmException;
import java.security.Permission;
import java.security.Permissions;
import java.security.SecureRandom;
import java.util.Map;
import java.util.function.Function;
import javax.annotation.Nonnull;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

/**
 * This is a convenience class to work-around issues with using the SLF4J
 * MDC class. It provides versions of async functionality that preserve
 * the MDC across the event and worker threads. It also contains many
 * methods to do the basic setup you need to get up and running. See the
 * SampleMain class in the test package for example usage.
 *
 * @author garricko
 */
public class VertxBase {
  private static final Logger log = LoggerFactory.getLogger(VertxBase.class);

  /**
   * Wrap a Handler in a way that will preserve the SLF4J MDC context.
   * The context from the current thread at the time of this method call
   * will be cached and restored within the wrapper at the time the
   * handler is invoked. This version delegates the handler call directly
   * on the thread that calls it.
   */
  public static <T> Handler<T> mdc(final Handler<T> handler) {
    final Map mdc = MDC.getCopyOfContextMap();

    return t -> {
      Map restore = MDC.getCopyOfContextMap();
      try {
        if (mdc == null) {
          MDC.clear();
        } else {
          MDC.setContextMap(mdc);
        }
        handler.handle(t);
      } finally {
        if (restore == null) {
          MDC.clear();
        } else {
          MDC.setContextMap(restore);
        }
      }
    };
  }

  /**
   * Wrap a Handler in a way that will preserve the SLF4J MDC context.
   * The context from the current thread at the time of this method call
   * will be cached and restored within the wrapper at the time the
   * handler is invoked. This version delegates the handler call using
   * {@link Context#runOnContext(Handler)} from the current context that
   * calls this method, ensuring the handler call will run on the correct
   * event loop.
   */
  public static <T> Handler<T> mdcEventLoop(final Handler<T> handler) {
    final Map mdc = MDC.getCopyOfContextMap();
    final Context context = Vertx.currentContext();

    return t -> context.runOnContext((v) -> {
      Map restore = MDC.getCopyOfContextMap();
      try {
        if (mdc == null) {
          MDC.clear();
        } else {
          MDC.setContextMap(mdc);
        }
        handler.handle(t);
      } finally {
        if (restore == null) {
          MDC.clear();
        } else {
          MDC.setContextMap(restore);
        }
      }
    });
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
    vertx.executeBlocking(mdc(future), ordered, mdcEventLoop(handler));
  }

  /**
   * Creates and seeds a secure random number generator, and registers a
   * timer in vertx to re-seed it periodically.
   *
   * <p>DO NOT call this method repeatedly. Call it once, and pass the
   * object around.</p>
   *
   * @param vertx a periodic timer will be registered with this vertx instance
   */
  @Nonnull
  public static SecureRandom createSecureRandom(@Nonnull Vertx vertx) {
    // The SHA-1 implementation is seeded via Native (/dev/random) but provides
    // non-blocking output with good cryptographic properties
    SecureRandom newRandom;
    try {
      newRandom = SecureRandom.getInstance("SHA1PRNG");
    } catch (NoSuchAlgorithmException e) {
      newRandom = new SecureRandom();
      log.warn("Unable to use SHA1PRNG for secure random source, defaulted to: " + newRandom.getAlgorithm() + " "
          + newRandom.getProvider(), e);
    }
    final SecureRandom random = newRandom;

    // Make sure default seeding happens now to avoid calling setSeed() too early
    random.nextBoolean();

    // Add a little more seed randomness every five minutes
    vertx.setPeriodic(300000L, id -> executeBlocking(vertx, f -> {
      Metric metric = new Metric(log.isTraceEnabled());
      random.setSeed(random.generateSeed(4));
      if (log.isTraceEnabled()) {
        log.trace("Re-seeded secure random " + metric.getMessage());
      }
      f.complete();
    }, r -> {
      if (r.failed()) {
        log.warn("Problem re-seeding secure random", r.cause());
      }
    }));

    return random;
  }

  /**
   * Make sure Vert.x is configured to use SLF4J, and send an INFO
   * statement to the log to make sure it is configured.
   */
  public static void initializeLogging() {
    // Vertx logs to JUL unless we tell it otherwise
    System.setProperty("vertx.logger-delegate-factory-class-name", "io.vertx.core.logging.SLF4JLogDelegateFactory");

    // Useful, but also serves to dump any logging related errors before
    // we redirect sout and serr to the logging framework below
    if (System.getProperty("log4j.configuration") != null) {
      log.info("Configured log4j using: " + System.getProperty("log4j.configuration"));
    } else {
      log.info("Configured log4j from the classpath");
    }
  }

  /**
   * Replace System.out and System.err so anything written to them
   * goes to SLF4J instead. You probably want to call {@link #initializeLogging()}
   * before this just in case logging is misconfigured (the errors
   * in that case will be written to the console, so you want the
   * console in its original condition at that point).
   *
   * <p>Log entries for standard out will be at the INFO level, and prefixed with
   * "System.out: ". Log entries for standard error will be at the ERROR level,
   * and prefixed with "System.err: ".</p>
   */
  public static void redirectConsoleToLog() {
    if (Boolean.getBoolean("java.security.debug")) {
      // Debugging the security manager and/or policy writes to the console and will
      // cause infinite recursion if we try to redirect the console since logging may
      // perform security checks
      return;
    }

    // Redirect console into slf4j log
    System.setOut(new PrintStream(System.out) {
      public void print(final String string) {
        log.info("System.out: {}", string);
      }

      public void println(final String string) {
        log.info("System.out: {}", string);
      }
    });
    System.setErr(new PrintStream(System.err) {
      public void print(final String string) {
        log.error("System.err: {}", string);
      }

      public void println(final String string) {
        log.error("System.err: {}", string);
      }
    });
  }

  /**
   * Determine the current working directory, either based on the "vertx.cwd"
   * or "user.dir" system property.
   */
  public static String workDir() {
    String workDir = System.getProperty("vertx.cwd");
    if (workDir == null) {
      workDir = System.getProperty("user.dir");
    }
    return workDir;
  }

  /**
   * Initialize the Java security manager. This will set permissions as needed
   * for basic Vert.x functionality to work, and you should pass in any additional
   * permissions the application code will need. Java system classes will receive
   * all permissions, and everything else will default to no permissions.
   */
  public static void startSecurityManager(Permission... appPermissions) throws Exception {
    setSecurityPolicy(appPermissions);
    enableSecurityManager();
  }

  public static void setSecurityPolicy(Permission... appPermissions) throws Exception {
    new BasePolicy() {
      @Override
      protected void addAppPermissions(Permissions appPerms) {
        for (Permission p : appPermissions) {
          if (p != null) {
            appPerms.add(p);
          }
        }
      }
    }.install();
  }

  public static void enableSecurityManager() {
    System.setSecurityManager(new SecurityManager());
    try {
      // Make sure the SecurityManager is doing something useful
      Files.exists(Paths.get(".."));
      log.error("Looks like the security sandbox is not working!");
    } catch (AccessControlException unused) {
      // Good, it's working
      log.info("Started the security manager");
    }
  }

  public static Router rootRouter(Vertx vertx, String defaultContext) {
    Router root = Router.router(vertx);
    root.route().handler(rc -> {
      // Make sure all requests start with a clean slate for logging
      MDC.clear();
      rc.next();
    });
    if (defaultContext != null) {
      root.get("/").handler(rc -> {
        rc.response().setStatusCode(302).putHeader("Location", defaultContext.endsWith("/") ? defaultContext
            : defaultContext + "/").end();
      });
    }
    return root;
  }

  /**
   * Add a JVM shutdown hook that will attempt to cleanly shut down Vert.x
   * and then optionally shut down other resources (like the database connection
   * pools).
   */
  public static void addShutdownHook(Vertx vertx, Closeable... toClose) {
    final Object lock = new Object();
    // Attempt to do a clean shutdown on JVM exit
    Runtime.getRuntime().addShutdownHook(new Thread(() -> {
      log.info("Trying to stop the server nicely");
      try {
        synchronized (lock) {
          // First shutdown Vert.x
          vertx.close(h -> {
            log.info("Vert.x stopped, now closing the connection pool");
            synchronized (lock) {
              // Then shutdown the database pool or other resources
              for (Closeable closeable : toClose) {
                try {
                  closeable.close();
                } catch (Exception e) {
                  log.warn("Error closing resource", e);
                }
              }
              log.info("Server stopped");
              lock.notify();
            }
          });
          lock.wait(30000);
        }
      } catch (Exception e) {
        log.warn("Error shutting down Vert.x", e);
      }
    }));
  }

  public static Handler<AsyncResult<JsonObject>> sendJson(RoutingContext rc) {
    return r -> {
      if (r.succeeded() && r.result() != null) {
        rc.response().putHeader("content-type", "application/json").end(r.result().encode() + '\n');
      } else {
        jsonApiFail(rc, r.cause());
      }
    };
  }

  public static Handler<AsyncResult<JsonObject>> sendJsonPretty(RoutingContext rc) {
    return r -> {
      if (r.succeeded() && r.result() != null) {
        rc.response().putHeader("content-type", "application/json").end(r.result().encodePrettily() + '\n');
      } else {
        jsonApiFail(rc, r.cause());
      }
    };
  }

  public static void jsonApiFail(RoutingContext rc) {
    jsonApiFail(rc, rc.failure());
  }

  public static void jsonApiFail(RoutingContext rc, Throwable t) {
    HttpServerResponse response = rc.response();

    if (isOrCausedBy(t, BadRequestException.class)) {
      log.debug("Validation error", t);
      response.setStatusCode(400).putHeader("content-type", "application/json").end(new JsonObject().put("error", t.getMessage()).encode() + '\n');
    } else if (isOrCausedBy(t, AuthenticationException.class)) {
      log.warn("Authentication error", t);
      response.setStatusCode(401).putHeader("content-type", "application/json").end(new JsonObject().put("error", t.getMessage()).encode() + '\n');
    } else if (isOrCausedBy(t, AuthorizationException.class)) {
      log.warn("Authorization error", t);
      response.setStatusCode(403).putHeader("content-type", "application/json").end(new JsonObject().put("error", t.getMessage()).encode() + '\n');
    } else {
      int statusCode = rc.statusCode();
      log.error("Unexpected error {}", statusCode, t);
      if (statusCode < 0) {
        statusCode = 500;
      }

      response.setStatusCode(statusCode);
      String message = response.getStatusMessage();

      // The default messages are misleading for these
      if (statusCode == 401) {
        message = "You need to login";
      } else if (statusCode == 403) {
        message = "You do not have permission";
      }

      response.setStatusCode(statusCode).putHeader("content-type", "application/json").end(new JsonObject().put("error", message).encode() + '\n');
    }
  }

  public static boolean isOrCausedBy(Throwable top, Class<? extends Throwable> type) {
    for (Throwable t : ExceptionUtils.getThrowables(top)) {
      if (type.isAssignableFrom(t.getClass())) {
        return true;
      }
    }
    return false;
  }

  /**
   * <p>Figure out the absolute, external URL for this server's root. For example:</p>
   *
   * <code>
   *   https://example.com/
   * </code>
   *
   * <p>The trailing '/' will be included in the returned value.</p>
   *
   * <p>This value is calculated based on three configuration properties. For the
   * example above these would be:</p>
   *
   * <code>
   *   public.url=https://example.com
   * </code>
   *
   * <p>Or, equivalently:</p>
   *
   * <code>
   *   public.proto=https
   *   public.host=example.com
   *   public.port=443
   * </code>
   *
   * @param keyToValueConfig this configuration must contain values for the three
   *                         keys above, or a ConfigMissingException exception will be thrown
   * @return the full public URL, including trailing slash
   */
  public static String absoluteRoot(Function<String, String> keyToValueConfig) {
    Config config = Config.from().custom(keyToValueConfig::apply).get();

    String url = config.getString("public.url");
    String proto;
    String host;
    String port;
    if (url == null) {
      proto = config.getString("public.proto");
      host = config.getString("public.host");
      port = config.getString("public.port");
      if (proto == null || host == null || port == null) {
        throw new ConfigMissingException("You must provide config property public.url or public.[proto,host,port]");
      }
    } else {
      PortInfo portInfo = PortInfo.parseUrl(url);
      proto = portInfo.proto();
      host = portInfo.host();
      port = Integer.toString(portInfo.port());
    }

    StringBuilder buf = new StringBuilder();
    buf.append(proto).append("://").append(host);
    switch (proto) {
    case "http":
      if (!port.equals("80")) {
        buf.append(':').append(port);
      }
      break;
    case "https":
      if (!port.equals("443")) {
        buf.append(':').append(port);
      }
      break;
    default:
      throw new RuntimeException("Configuration error: public.proto must be either http or https");
    }
    buf.append('/');
    return buf.toString();
  }

  /**
   * <p>This calls {@link #absoluteRoot(Function)} and then appends the mount point
   * of the router handling this request. For example, if you have a root router
   * and then add a sub router using context "/foo" this might return:</p>
   *
   * <code>
   *   https://example.com/foo/
   * </code>
   *
   * @param keyToValueConfig configuration containing values for public.url or public.proto,
   *                         public.host, and public.port
   * @param rc the context handling a particular request (used to determine the mount point)
   * @return the full public URL, including mount point and trailing slash
   */
  public static String absoluteContext(Function<String, String> keyToValueConfig, RoutingContext rc) {
    String root = absoluteRoot(keyToValueConfig);
    String context = rc.mountPoint();

    if (context == null) {
      return root;
    }
    return root + context.substring(1);
  }

  public static String absolutePath(Function<String, String> keyToValueConfig, RoutingContext rc) {
    String root = absoluteRoot(keyToValueConfig);
    String context = rc.normalisedPath();

    if (context == null) {
      return root;
    }
    return root + context.substring(1);
  }
}
