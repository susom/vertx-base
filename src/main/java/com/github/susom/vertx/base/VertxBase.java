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
import com.github.susom.database.Metric;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import java.io.Closeable;
import java.io.FilePermission;
import java.io.PrintStream;
import java.lang.reflect.ReflectPermission;
import java.net.NetPermission;
import java.net.SocketPermission;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Paths;
import java.security.AllPermission;
import java.security.NoSuchAlgorithmException;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.security.Policy;
import java.security.ProtectionDomain;
import java.security.SecureRandom;
import java.security.SecurityPermission;
import java.util.HashSet;
import java.util.Map;
import java.util.PropertyPermission;
import java.util.Set;
import java.util.WeakHashMap;
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
      log.trace("Re-seeded secure random " + metric.getMessage());
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
    String tempDir = System.getProperty("java.io.tmpdir");
    String workDir = workDir();
    String userDir = System.getProperty("user.home");
    String javaDir = System.getProperty("java.home");

//    log.debug("Directories for initializing the SecurityManager:\n  temp: " + tempDir + "\n  work: "
//        + workDir + "\n  java: " + javaDir + "\n  user: " + userDir);

    // Walk the classpath to figure out all the relevant codebase locations for our policy
    String javaHome = javaDir;
    if (javaHome.endsWith("/jre")) {
      javaHome = javaHome.substring(0, javaHome.length()-5);
    }
    Set<String> jdkLocations = new HashSet<>();
    Set<String> appLocations = new HashSet<>();
    String[] classpath = System.getProperty("java.class.path").split(":");
    for (String entry : classpath) {
      entry = Paths.get(entry).toAbsolutePath().normalize().toString();
      if (entry.startsWith(javaHome)) {
        jdkLocations.add(entry);
      } else {
        appLocations.add(entry);
      }
//      if (log.isTraceEnabled()) {
//        log.trace("Classpath entry: " + entry);
//      }
    }
    for (URL url : ((URLClassLoader)Thread.currentThread().getContextClassLoader()).getURLs()) {
      String entry = Paths.get(url.toURI()).toAbsolutePath().normalize().toString();
      appLocations.add(entry);
//      if (log.isTraceEnabled()) {
//        log.trace("Policy class loader url: " + entry);
//      }
    }

    Policy.setPolicy(new Policy() {
      private final WeakHashMap<String, PermissionCollection> cache = new WeakHashMap<>();

      @Override
      public boolean implies(ProtectionDomain domain, Permission permission) {
        String path = domain.getCodeSource().getLocation().getPath();
        PermissionCollection pc;

        synchronized (cache) {
          pc = cache.get(path);
        }

        if (pc == null) {
          pc = getPermissions(domain);

          synchronized (cache) {
            cache.put(path, pc);
          }
        }

        return pc.implies(permission);
      }

      @Override
      public PermissionCollection getPermissions(ProtectionDomain domain) {
        String path = domain.getCodeSource().getLocation().getPath();
        if (path.endsWith("/")) {
          path = path.substring(0, path.length() - 1);
        }
        path = path.replaceAll("%20", " ");
        if (jdkLocations.contains(path) || path.startsWith(javaDir)) {
//          log.trace("Returning all permissions for codesource: {}", path);
          Permissions jdkPerms = new Permissions();
          jdkPerms.add(new AllPermission());
          return jdkPerms;
        } else if (appLocations.contains(path)) {
//          log.trace("Returning application permissions for codesource: {}", path);
          Permissions appPerms = new Permissions();

          for (Permission permission : appPermissions) {
            if (permission != null) {
              appPerms.add(permission);
            }
          }

          for (String entry : appLocations) {
            // Make sure we can read the classpath files (e.g. Maven jars) and directories
            appPerms.add(new FilePermission(entry, "read"));
            if (!entry.endsWith(".jar")) {
              appPerms.add(new FilePermission(entry + "/-", "read"));
            }
          }

          // Files and directories the app will access
          appPerms.add(new FilePermission(workDir + "/local.properties", "read"));
          appPerms.add(new FilePermission(workDir + "/.vertx", "read,write,delete"));
          appPerms.add(new FilePermission(workDir + "/.vertx/-", "read,write,delete"));
          appPerms.add(new FilePermission(workDir + "/conf/-", "read"));
          appPerms.add(new FilePermission(workDir + "/logs/-", "read,write"));
          appPerms.add(new FilePermission(tempDir, "read,write"));
          // Work-around for the fact Vert.x always checks filesystem before loading classpath resources
          appPerms.add(new FilePermission(workDir + "/static/-", "read"));

          // Accept connections on any dynamic port (this is different from listening on the port)
          appPerms.add(new SocketPermission("localhost:1024-", "accept"));

          // We register a shutdown hook to stop Vert.x and clean up the database pool
          appPerms.add(new RuntimePermission("shutdownHooks"));
          appPerms.add(new RuntimePermission("modifyThread"));

          // Everything tries to read some system property
          appPerms.add(new PropertyPermission("*", "read"));

          // These seem like bugs in vertx/netty (should not fail if these permissions are not granted)
          appPerms.add(new RuntimePermission("setIO"));
          appPerms.add(new PropertyPermission("io.netty.noJdkZlibDecoder", "write"));
          appPerms.add(new PropertyPermission("sun.nio.ch.bugLevel", "write"));

          // Emailer does DNS lookup on localhost hostname
          appPerms.add(new SocketPermission("*", "resolve"));

          // Not sure about these
          appPerms.add(new ReflectPermission("suppressAccessChecks"));
          appPerms.add(new RuntimePermission("accessDeclaredMembers"));
          appPerms.add(new RuntimePermission("getClassLoader"));
          appPerms.add(new RuntimePermission("getStackTrace"));
          appPerms.add(new RuntimePermission("setContextClassLoader"));
          appPerms.add(new RuntimePermission("loadLibrary.sunec"));
          appPerms.add(new RuntimePermission("accessClassInPackage.sun.*"));
          appPerms.add(new SecurityPermission("putProviderProperty.SunJCE"));
          appPerms.add(new SecurityPermission("putProviderProperty.SunEC"));
          appPerms.add(new NetPermission("getNetworkInformation"));
          appPerms.add(new FilePermission("/proc/sys/net/core/somaxconn", "read"));
          appPerms.add(new FilePermission("/etc/hosts", "read"));

          return appPerms;
        }
//        log.trace("Returning no permissions for codesource: {}", path);
        return new Permissions();
      }
    });

    System.setSecurityManager(new SecurityManager());
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

  public static void jsonApiFail(RoutingContext rc) {
    jsonApiFail(rc, rc.failure());
  }

  public static void jsonApiFail(RoutingContext rc, Throwable t) {
    if (isOrCausedBy(t, BadRequestException.class)) {
      log.debug("Validation error", t);
      rc.response().setStatusCode(400).end(new JsonObject().put("error", t.getMessage()).encode());
    } else {
      log.error("Unexpected error", t);
      rc.response().setStatusCode(500).end();
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

  public static String absoluteRoot(Function<String, String> keyToValueConfig/*, RoutingContext rc*/) {
    Config config = Config.from().custom(keyToValueConfig::apply).get();

    String proto = config.getStringOrThrow("public.proto");
    String host = config.getStringOrThrow("public.host");
    String port = config.getStringOrThrow("public.port");

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
