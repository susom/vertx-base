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
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nonnull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

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
      ClassLoader cl = Thread.currentThread().getContextClassLoader();
      PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver(cl) {};
      // We want to use classpath*: because that searches over the entire classpath
      // rather than allowing one directory to mask a later one
      Resource[] resources = resolver.getResources("classpath*:" + dir + pattern);
      if (resources != null) {
        for (Resource resource : resources) {
          if (resource.isReadable()) {
            if (ClassPathResource.class.isAssignableFrom(resource.getClass())) {
              String resourcePath = ((ClassPathResource) resource).getPath();
              if (resourcePath.endsWith("/")) {
                continue;
              }
              String servePath = prefix + resourcePath.substring(resourcePath.indexOf(dir) + dir.length());
              if (pathToResource.containsKey(servePath)) {
                log.trace("Skipping duplicate classpath resource {} ({})", servePath, resourcePath);
                continue;
              }
              // This copies the file into the .vertx cache directory to be served via sendFile()
              File file = vertx.resolveFile(resourcePath);
              log.trace("Adding classpath resource {} ({})", servePath, resourcePath);
              pathToResource.put(servePath, file);
            } else if (resource instanceof FileSystemResource) {
              File file = ((FileSystemResource) resource).getFile();
              if (file.isDirectory()) {
                continue;
              }
              String resourcePath = file.getPath();
              // This isn't quite correct because it assumes the absolute path does
              // not contain dir, but I haven't figured out how to know the base yet
              String servePath = prefix + resourcePath.substring(resourcePath.indexOf("/" + dir) + 1).substring(dir.length());
              if (pathToResource.containsKey(servePath)) {
                log.trace("Skipping duplicate file resource {} ({})", servePath, resourcePath);
                continue;
              }
              log.trace("Adding file resource {} ({})", servePath, resourcePath);
              pathToResource.put(servePath, file);
            } else if (resource instanceof UrlResource) {
              String fullPath = resource.getURL().getPath();
              if (fullPath.endsWith("/")) {
                continue;
              }
              String resourcePath = fullPath.substring(fullPath.indexOf(".jar!/") + 6);
              String servePath = prefix + resourcePath.substring(resourcePath.indexOf(dir) + dir.length());
              if (pathToResource.containsKey(servePath)) {
                log.trace("Skipping duplicate classpath url resource {} ({})", servePath, resourcePath);
                continue;
              }
              // This copies the file into the .vertx cache directory to be served via sendFile()
              File file = vertx.resolveFile(resourcePath);
              log.trace("Adding classpath url resource {} ({})", servePath, resourcePath);
              pathToResource.put(servePath, file);
            } else {
              log.warn("Skipping resource because it is an unknown class ({}): {}", resource.getClass(), resource);
            }
          } else {
            log.trace("Skipping resource because it is not readable: {}", resource);
          }
        }
      }
    } catch (Exception e) {
      throw new RuntimeException("Could not locate File for resource dir: " + dir, e);
    }

    return this;
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
