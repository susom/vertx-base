/*
 * Copyright 2016 The Board of Trustees of The Leland Stanford Junior University.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.github.susom.vertx.base;

/**
 * Convenient way to extract protocol, hostname, and port from a URL and/or
 * pass the triplet around.
 *
 * @author garricko
 */
public class PortInfo {
  private final String proto;
  private final String host;
  private final int port;

  public PortInfo(String proto, String host, int port) {
    this.proto = proto;
    this.host = host;
    this.port = port;
  }

  /**
   * Read the protocol, host, and port from a URL-like string. This
   * is not a full URL parsing scheme. The URL must use only the http
   * or https protocol (lowercase). Default ports 80 and 443 will be
   * inferred as appropriate.
   *
   * @param url a url-like string (e.g. http://example.com/foo), or null
   * @return the parsed protocol, host, port triplet, or null if url was null
   * @throws RuntimeException if the url could not be parsed
   */
  public static PortInfo parseUrl(String url) {
    if (url == null) {
      return null;
    }

    String proto;
    String host;
    int port;

    String[] hostAndPort;
    if (url.startsWith("https://")) {
      proto = "https";
      hostAndPort = url.substring("https://".length()).split("/")[0].split(":");
    } else if (url.startsWith("http://")) {
      proto = "http";
      hostAndPort = url.substring("http://".length()).split("/")[0].split(":");
    } else {
      throw new RuntimeException("Invalid protocol for url: " + url);
    }

    if (hostAndPort.length == 1) {
      host = hostAndPort[0];
      port = proto.equals("http") ? 80 : 443;
    } else {
      host = hostAndPort[0];
      port = Integer.parseInt(hostAndPort[1]);
    }

    return new PortInfo(proto, host, port);
  }

  public String proto() {
    return proto;
  }

  public String host() {
    return host;
  }

  public int port() {
    return port;
  }
}
