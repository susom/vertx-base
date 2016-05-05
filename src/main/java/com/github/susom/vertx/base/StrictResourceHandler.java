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
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nonnull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
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

  // TODO browser caching (*.cache.*, *.nocache.*, regular)

  public StrictResourceHandler(Vertx vertx) {
    this.vertx = (VertxInternal) vertx;
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
      Resource[] resources = resolver.getResources(dir + pattern);
      if (resources != null) {
        for (Resource resource : resources) {
          if (resource.isReadable()) {
            if (resource instanceof ClassPathResource) {
              String resourcePath = ((ClassPathResource) resource).getPath();
              if (resourcePath.endsWith("/")) {
                continue;
              }
              String servePath = prefix + resourcePath.substring(resourcePath.indexOf(dir) + dir.length());
              // This copies the file into the .vertx cache directory to be served via sendFile()
              File file = vertx.resolveFile(resourcePath);
              log.debug("Adding classpath resource " + servePath + " (" + resourcePath + ")");
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
              log.debug("Adding file resource " + servePath + " (" + resourcePath + ")");
              pathToResource.put(servePath, file);
            }
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
        log.debug("Stripping mount point from path: " + mountPoint);
        path = path.substring(mountPoint.length());
      }

      if (path.length() == 0) {
        rc.response().setStatusCode(302).putHeader("location", rc.request().absoluteURI() + "/").end();
        return;
      }

      if (path.equals("/")) {
        path = path + rootIndex;
      }

      File file = pathToResource.get(path);
      if (file == null) {
        // TODO trace rather than warning
        log.warn("Path not found: " + path + " so skipping this handler");
        rc.next();
        return;
      }

      log.debug("Sending file: " + file.getAbsolutePath());
      rc.response().sendFile(file.getAbsolutePath());
    }
  }
}
