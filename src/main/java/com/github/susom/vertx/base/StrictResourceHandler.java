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

import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.impl.VertxInternal;
import io.vertx.ext.web.RoutingContext;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import javax.annotation.Nonnull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static io.netty.handler.codec.http.HttpResponseStatus.NOT_FOUND;

/**
 * Serve resources from the classpath in a safe way. Rather than taking a path
 * from the (untrusted) request and trying to find it in the classpath, we scan
 * the classpath to locate resources we want to serve, and store them in a map.
 * The untrusted paths are looked up in the map and only served if they match
 * exactly.
 */
public class StrictResourceHandler implements Handler<RoutingContext> {
  private static final Logger log = LoggerFactory.getLogger(StrictResourceHandler.class);
  private final Map<String, File> pathToResource = new HashMap<>();
  private final VertxInternal vertx;
  private String rootIndex = "index.html";
  private boolean warnIfNotFound;

  public StrictResourceHandler(Vertx vertx) {
    this.vertx = (VertxInternal) vertx;
  }

  /**
   * Emit a log entry at WARN level if the requested path cannot be found and we are
   * falling through to the next handler. By default it will be logged at TRACE level.
   */
  @Nonnull
  public StrictResourceHandler warnIfNotFound() {
    warnIfNotFound = true;
    return this;
  }

  @Nonnull
  public StrictResourceHandler addDir(@Nonnull String dir) {
    return addDir(dir, "**/*", "");
  }

  /**
   * Add a directory from the classpath, including all contained files and
   * directories recursively.
   *
   * @param dir a directory relative to the classpath root, (e.g. "static/mystuff")
   *            where resources will be loaded from
   * @param prefix a prefix that will be added to the resources within dir (e.g. "mystuff");
   *               may be the empty string if you don't want an additional prefix
   */
  @Nonnull
  public StrictResourceHandler addDir(@Nonnull String dir, @Nonnull String pattern, @Nonnull String prefix) {
    if (!dir.endsWith("/")) {
      dir = dir + "/";
    }
    if (!prefix.startsWith("/")) {
      prefix = "/" + prefix;
    }
    if (!prefix.endsWith("/")) {
      prefix = prefix + "/";
    }

    try {
      List<String> resourcePaths = findClasspathResources(dir, pattern);
      for (String resourcePath : resourcePaths) {
        String relativePath = resourcePath.substring(resourcePath.indexOf(dir) + dir.length());
        String servePath = prefix + relativePath;
        if (pathToResource.containsKey(servePath)) {
          log.trace("Skipping duplicate classpath resource {} ({})", servePath, resourcePath);
          continue;
        }
        // This copies the file into the .vertx cache directory to be served via sendFile()
        File file = vertx.resolveFile(resourcePath);
        log.trace("Adding classpath resource {} ({})", servePath, resourcePath);
        pathToResource.put(servePath, file);
      }
    } catch (Exception e) {
      throw new RuntimeException("Could not locate File for resource dir: " + dir, e);
    }

    return this;
  }

  /**
   * Scans the entire classpath for resources under {@code dir} whose path relative to
   * {@code dir} matches the Ant-style {@code pattern}.  Returns the resource paths
   * (relative to the classpath root) of every matching, non-directory entry found.
   *
   * <p>This method searches both exploded-directory classpath entries and JAR files,
   * mirroring the {@code classpath*:} prefix behaviour of Spring's
   * {@code PathMatchingResourcePatternResolver}.
   */
  private List<String> findClasspathResources(String dir, String pattern) throws IOException {
    ClassLoader cl = Thread.currentThread().getContextClassLoader();
    List<String> results = new ArrayList<>();

    // Enumerate every classpath root that contains the target directory
    Enumeration<URL> dirUrls = cl.getResources(dir.endsWith("/") ? dir.substring(0, dir.length() - 1) : dir);
    while (dirUrls.hasMoreElements()) {
      URL url = dirUrls.nextElement();
      String protocol = url.getProtocol();

      if ("file".equals(protocol)) {
        // Exploded directory on the filesystem
        Path base;
        try {
          base = Paths.get(url.toURI());
        } catch (java.net.URISyntaxException e) {
          throw new IOException("Invalid URI for classpath URL: " + url, e);
        }
        if (!Files.isDirectory(base)) {
          continue;
        }
        Files.walkFileTree(base, new SimpleFileVisitor<Path>() {
          @Override
          public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
            String relative = base.relativize(file).toString().replace(File.separatorChar, '/');
            if (AntPathMatcher.match(pattern, relative)) {
              results.add(dir + relative);
            }
            return FileVisitResult.CONTINUE;
          }
        });
      } else if ("jar".equals(protocol)) {
        // Resource inside a JAR: jar:file:/path/to/foo.jar!/some/dir
        String jarPath = url.getPath(); // e.g. file:/path/to/foo.jar!/some/dir
        int separatorIdx = jarPath.indexOf("!/");
        if (separatorIdx == -1) {
          continue;
        }
        String jarFilePath = jarPath.substring("file:".length(), separatorIdx);
        try (JarFile jarFile = new JarFile(jarFilePath)) {
          String dirPrefix = dir.endsWith("/") ? dir : dir + "/";
          Enumeration<JarEntry> entries = jarFile.entries();
          while (entries.hasMoreElements()) {
            JarEntry entry = entries.nextElement();
            String name = entry.getName();
            if (entry.isDirectory() || !name.startsWith(dirPrefix)) {
              continue;
            }
            String relative = name.substring(dirPrefix.length());
            if (AntPathMatcher.match(pattern, relative)) {
              results.add(name);
            }
          }
        }
      }
    }

    return results;
  }

  /**
   * Indicate the file (e.g. "index.html") that should be served on requests for path "/".
   */
  public StrictResourceHandler rootIndex(String indexFile) {
    this.rootIndex = indexFile;

    return this;
  }

  public StrictResourceHandler remove(String... paths) {
    for (String path : paths) {
      if (!path.startsWith("/")) {
        path = "/" + path;
      }
      if (!pathToResource.containsKey(path)) {
        throw new RuntimeException("Cannot remove path because it does not exist: " + path);
      }
      pathToResource.remove(path);
    }

    return this;
  }

  public StrictResourceHandler rename(String path, String newPath) {
    if (!path.startsWith("/")) {
      path = "/" + path;
    }
    if (!newPath.startsWith("/")) {
      newPath = "/" + newPath;
    }

    if (pathToResource.containsKey(path)) {
      pathToResource.put(newPath, pathToResource.remove(path));
    } else {
      throw new RuntimeException("Cannot rename path because it does not exist: " + path);
    }

    return this;
  }

  public void handle(RoutingContext rc) {
    HttpServerRequest request = rc.request();
    if (request.method() != HttpMethod.GET && request.method() != HttpMethod.HEAD) {
      if (log.isTraceEnabled()) log.trace("Not GET or HEAD so ignoring request");
      rc.next();
    } else {
      String path = rc.normalisedPath();
      // if the normalized path is null it cannot be resolved
      if (path == null) {
        log.warn("Invalid path: " + request.path() + " so returning 404");
        rc.fail(NOT_FOUND.code());
        return;
      }

      String mountPoint = rc.mountPoint();
      if (mountPoint != null && path.startsWith(mountPoint)) {
        log.trace("Stripping mount point from path: {}", mountPoint);
        path = path.substring(mountPoint.length());
      }

      if (path.length() == 0) {
        String q = rc.request().query();
        if (q == null) {
          q = "";
        } else {
          q = "?" + q;
        }
        rc.response().setStatusCode(302).putHeader("location", (mountPoint == null ? "" : mountPoint) + "/" + q).end();
        return;
      }

      if (path.equals("/")) {
        path = path + rootIndex;
      }

      File file = pathToResource.get(path);
      if (file == null) {
        if (warnIfNotFound) {
          log.warn("Path not found: " + path + " so skipping this handler");
        } else {
          log.trace("Path not found: {} so skipping this handler", path);
        }
        rc.next();
        return;
      }

      log.debug("Sending file: {}", file.getAbsolutePath());

      // Allow naming convention to control caching behavior
      if (path.contains(".nocache.")) {
        ZonedDateTime now = ZonedDateTime.now(ZoneId.of("GMT"));
        rc.response().headers()
            .add("Date", DateTimeFormatter.RFC_1123_DATE_TIME.format(now))
            .add("Expires", DateTimeFormatter.RFC_1123_DATE_TIME.format(now.minus(1, ChronoUnit.DAYS)))
            .add("Pragma", "no-cache")
            .add("Cache-control", "no-cache, no-store, must-revalidate");
      } else if (path.contains(".cache.")) {
        ZonedDateTime now = ZonedDateTime.now(ZoneId.of("GMT"));
        rc.response().headers()
            .add("Date", DateTimeFormatter.RFC_1123_DATE_TIME.format(now))
            .add("Expires", DateTimeFormatter.RFC_1123_DATE_TIME.format(now.plus(1, ChronoUnit.YEARS)))
            .add("Cache-control", "max-age=31536000");
      }

      rc.response().sendFile(file.getAbsolutePath());
    }
  }
}
