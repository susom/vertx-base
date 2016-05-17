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
import java.io.Closeable;
import java.io.FilePermission;
import java.io.PrintStream;
import java.lang.reflect.ReflectPermission;
import java.net.MalformedURLException;
import java.net.NetPermission;
import java.net.SocketPermission;
import java.security.AllPermission;
import java.security.CodeSource;
import java.security.NoSuchAlgorithmException;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.security.Policy;
import java.security.SecureRandom;
import java.security.SecurityPermission;
import java.util.HashSet;
import java.util.Map;
import java.util.PropertyPermission;
import java.util.Set;
import javax.annotation.Nonnull;
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

    // Add a little more seed randomness every hour
    vertx.setPeriodic(3600000L, (id) -> random.setSeed(random.generateSeed(4)));

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
  public static void startSecurityManager(Permission... appPermissions) throws MalformedURLException {
    String tempDir = System.getProperty("java.io.tmpdir");
    String workDir = workDir();
    String userDir = System.getProperty("user.home");
    String javaDir = System.getProperty("java.home");

    log.debug("Directories for initializing the SecurityManager:\n  temp: " + tempDir + "\n  work: "
        + workDir + "\n  java: " + javaDir + "\n  user: " + userDir);

    Permissions appPerms = new Permissions();

    for (Permission permission : appPermissions) {
      appPerms.add(permission);
    }

    // Walk the classpath to figure out all the relevant codebase locations for our policy
    String javaHome = javaDir;
    if (javaHome.endsWith("/jre")) {
      javaHome = javaHome.substring(0, javaHome.length()-5);
    }
    Set<String> jdkLocations = new HashSet<>();
    Set<String> appLocations = new HashSet<>();
    String[] classpath = System.getProperty("java.class.path").split(":");
    for (String entry : classpath) {
      if (entry.startsWith(javaHome)) {
        jdkLocations.add(entry);
      } else {
        appLocations.add(entry);

        // Make sure we can read the classpath files (e.g. Maven jars)
        appPerms.add(new FilePermission(entry, "read"));
      }
      if (log.isTraceEnabled()) {
        log.trace("Classpath entry: " + entry);
      }
    }

    // Files and directories the app will access
    appPerms.add(new FilePermission(workDir + "/local.properties", "read"));
    appPerms.add(new FilePermission(workDir + "/.vertx", "read,write,delete"));
    appPerms.add(new FilePermission(workDir + "/.vertx/-", "read,write,delete"));
    appPerms.add(new FilePermission(workDir + "/conf/-", "read"));
    appPerms.add(new FilePermission(workDir + "/logs/-", "read,write"));
    appPerms.add(new FilePermission(tempDir, "read,write"));

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
    appPerms.add(new RuntimePermission("setContextClassLoader"));
    appPerms.add(new RuntimePermission("loadLibrary.sunec"));
    appPerms.add(new RuntimePermission("accessClassInPackage.sun.*"));
    appPerms.add(new SecurityPermission("putProviderProperty.SunJCE"));
    appPerms.add(new SecurityPermission("putProviderProperty.SunEC"));
    appPerms.add(new NetPermission("getNetworkInformation"));
    appPerms.add(new FilePermission("/proc/sys/net/core/somaxconn", "read"));

    Permissions jdkPerms = new Permissions();
    jdkPerms.add(new AllPermission());

    Permissions noPerms = new Permissions();

    Policy.setPolicy(new Policy() {
      @Override
      public PermissionCollection getPermissions(CodeSource codesource) {
        String path = codesource.getLocation().getPath();
        if (path.endsWith("/")) {
          path = path.substring(0, path.length() - 1);
        }
        path = path.replaceAll("%20", " ");
        if (jdkLocations.contains(path) || path.startsWith(javaDir)) {
          log.trace("Returning all permissions for codesource: {}", path);
          return jdkPerms;
        } else if (appLocations.contains(path)) {
          log.trace("Returning application permissions for codesource: {}", path);
          return appPerms;
        }
        log.trace("Returning no permissions for codesource: {}", path);
        return noPerms;
      }
    });

    System.setSecurityManager(new SecurityManager() {
      final Set<Permission> alreadyDenied = new HashSet<>();

      public void checkPermission(Permission perm, Object context) {
        try {
          super.checkPermission(perm, context);
        } catch (SecurityException e) {
          synchronized (alreadyDenied) {
            if (!alreadyDenied.contains(perm)) {
              log.warn("Denying permission: " + perm + " context: " + context, e);
              alreadyDenied.add(perm);
            }
          }
          throw e;
        }
      }

      public void checkPermission(Permission perm) {
        try {
          super.checkPermission(perm);
        } catch (SecurityException e) {
          synchronized (alreadyDenied) {
            if (!alreadyDenied.contains(perm)) {
              log.warn("Denying permission: " + perm, e);
              alreadyDenied.add(perm);
            }
          }
          throw e;
        }
      }
    });
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
}
