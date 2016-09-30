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
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nonnull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.AntPathMatcher;

import static io.netty.handler.codec.http.HttpResponseStatus.NOT_FOUND;

/**
 * Serve resources from the filesystem in a safe way. Rather than taking a path
 * from the (untrusted) request and trying to find it on the filesystem, we scan
 * the filesystem to locate files we want to serve, and store them in a map.
 * The untrusted paths are looked up in the map and only served if they match
 * exactly.
 */
public class StrictFileHandler implements Handler<RoutingContext> {
  private static final Logger log = LoggerFactory.getLogger(StrictFileHandler.class);
  private final Map<String, File> pathToFile = new HashMap<>();
  private final VertxInternal vertx;
  private String rootIndex = "index.html";

  public StrictFileHandler(Vertx vertx) {
    this.vertx = (VertxInternal) vertx;
  }

  @Nonnull
  public StrictFileHandler addDir(@Nonnull String dir) {
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
  public StrictFileHandler addDir(@Nonnull String dir, @Nonnull String pattern, @Nonnull String prefix) {
    if (!dir.endsWith("/")) {
      dir = dir + "/";
    }
    if (!prefix.startsWith("/")) {
      prefix = "/" + prefix;
    }
    if (!prefix.endsWith("/")) {
      prefix = prefix + "/";
    }

    final String finalDir = dir;
    final String finalPrefix = prefix;

    try {
      Files.walkFileTree(Paths.get(finalDir), new SimpleFileVisitor<Path>() {
        AntPathMatcher matcher = new AntPathMatcher();

        @Override
        public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
          String resourcePath = file.toString();
          if (matcher.match(pattern, resourcePath)) {
            // This isn't quite correct because it assumes the absolute path does
            // not contain dir, but I haven't figured out how to know the base yet
            String servePath = finalPrefix + resourcePath.substring(
                resourcePath.indexOf("/" + finalDir) + 1).substring(finalDir.length());
            if (log.isTraceEnabled()) {
              log.trace("Adding file as " + servePath + " (" + resourcePath + ")");
            }
            pathToFile.put(servePath, file.toFile());
            // This copies the file into the .vertx cache directory to be served via sendFile()
            File serveFile = vertx.resolveFile(resourcePath);
            pathToFile.put(servePath, serveFile);
          } else {
            if (log.isTraceEnabled()) {
              log.trace("Path did not match pattern \"" + pattern + "\": " + resourcePath);
            }
          }

          return super.visitFile(file, attrs);
        }
      });
    } catch (Exception e) {
      throw new RuntimeException("Could not locate File for resource dir: " + dir, e);
    }

    return this;
  }

  /**
   * Indicate the file (e.g. "index.html") that should be served on requests for path "/".
   */
  public StrictFileHandler rootIndex(String indexFile) {
    this.rootIndex = indexFile;

    return this;
  }

  public StrictFileHandler remove(String... paths) {
    for (String path : paths) {
      if (!path.startsWith("/")) {
        path = "/" + path;
      }
      if (!pathToFile.containsKey(path)) {
        throw new RuntimeException("Cannot remove path because it does not exist: " + path);
      }
      pathToFile.remove(path);
    }

    return this;
  }

  public StrictFileHandler rename(String path, String newPath) {
    if (!path.startsWith("/")) {
      path = "/" + path;
    }
    if (!newPath.startsWith("/")) {
      newPath = "/" + newPath;
    }

    if (pathToFile.containsKey(path)) {
      pathToFile.put(newPath, pathToFile.remove(path));
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
        log.debug("Stripping mount point from path: " + mountPoint);
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

      File file = pathToFile.get(path);
      if (file == null) {
        // TODO trace rather than warning
        log.warn("Path not found: " + path + " so skipping this handler");
        rc.next();
        return;
      }

      // Allow naming convention to control caching behavior
      if (path.contains(".nocache.")) {
        ZonedDateTime now = ZonedDateTime.now(ZoneId.of("GMT"));
        rc.response().headers()
            .add("Date", DateTimeFormatter.RFC_1123_DATE_TIME.format(now))
            .add("Expires", DateTimeFormatter.RFC_1123_DATE_TIME.format(now.minus(1, ChronoUnit.DAYS)))
            .add("Pragma", "no-cache")
            .add("Cache-control", "no-cache, no-store, must-revalidate");
        if (log.isTraceEnabled()) {
          log.trace("Sending file (no-cache): " + file.getAbsolutePath());
        }
      } else if (path.contains(".cache.")) {
        ZonedDateTime now = ZonedDateTime.now(ZoneId.of("GMT"));
        rc.response().headers()
            .add("Date", DateTimeFormatter.RFC_1123_DATE_TIME.format(now))
            .add("Expires", DateTimeFormatter.RFC_1123_DATE_TIME.format(now.plus(1, ChronoUnit.YEARS)))
            .add("Cache-control", "max-age=31536000");
        if (log.isTraceEnabled()) {
          log.trace("Sending file (cache-forever): " + file.getAbsolutePath());
        }
      }

      rc.response().sendFile(file.getAbsolutePath());
    }
  }
}
