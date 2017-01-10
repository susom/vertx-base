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

import java.io.FilePermission;
import java.lang.reflect.ReflectPermission;
import java.net.NetPermission;
import java.net.SocketPermission;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Paths;
import java.security.AllPermission;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.security.Policy;
import java.security.ProtectionDomain;
import java.security.SecurityPermission;
import java.util.HashSet;
import java.util.PropertyPermission;
import java.util.Set;
import java.util.WeakHashMap;

import static com.github.susom.vertx.base.VertxBase.workDir;

/**
 * This is just a convenient base class you can extend to customize the
 * security policy for your application.
 *
 * @author garricko
 */
public class BasePolicy extends Policy {
  private final WeakHashMap<String, PermissionCollection> cache = new WeakHashMap<>();
  protected final String tempDir;
  protected final String workDir;
  protected final String userDir;
  protected final String javaDir;
  protected final boolean debug;
  private final Set<String> jdkLocations = new HashSet<>();
  private final Set<String> appLocations = new HashSet<>();

  public BasePolicy() throws Exception {
    tempDir = System.getProperty("java.io.tmpdir");
    workDir = workDir();
    userDir = System.getProperty("user.home");
    javaDir = System.getProperty("java.home");
    debug = Boolean.getBoolean("java.security.debug");

    // Walk the classpath to figure out all the relevant codebase locations for our policy
    String javaHome = javaDir;
    if (javaHome.endsWith("/jre")) {
      javaHome = javaHome.substring(0, javaHome.length()-5);
    }
    String[] classpath = System.getProperty("java.class.path").split(":");
    for (String entry : classpath) {
      entry = Paths.get(entry).toAbsolutePath().normalize().toString();
      if (entry.startsWith(javaHome)) {
        jdkLocations.add(entry);
      } else {
        appLocations.add(entry);
      }
      if (debug) {
        System.out.println("Security policy detected classpath entry: " + entry);
      }
    }
    for (URL url : ((URLClassLoader)Thread.currentThread().getContextClassLoader()).getURLs()) {
      String entry = Paths.get(url.toURI()).toAbsolutePath().normalize().toString();
      appLocations.add(entry);
      if (debug) {
        System.out.println("Policy class loader url: " + entry);
      }
    }
  }

  public String dirs() {
    return "Directories for initializing the security policy:\n  temp: " + tempDir + "\n  work: "
        + workDir + "\n  java: " + javaDir + "\n  user: " + userDir;
  }

  public void install() {
    Policy.setPolicy(this);
  }

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

  protected void addAppPermissions(Permissions appPerms) {
    // Hook for subclasses to add their own permissions
  }

  protected Permissions jdkPermissions() {
    Permissions jdkPerms = new Permissions();
    jdkPerms.add(new AllPermission());
    return jdkPerms;
  }

  @Override
  public PermissionCollection getPermissions(ProtectionDomain domain) {
    String path = domain.getCodeSource().getLocation().getPath();
    if (path.endsWith("/")) {
      path = path.substring(0, path.length() - 1);
    }
    path = path.replaceAll("%20", " ");
    if (jdkLocations.contains(path) || path.startsWith(javaDir)) {
      if (debug) {
        System.out.println("Returning all permissions for code source: " + path);
      }
      return jdkPermissions();
    } else if (appLocations.contains(path)) {
      if (debug) {
        System.out.println("Returning application permissions for code source: " + path);
      }
      Permissions appPerms = new Permissions();

      addAppPermissions(appPerms);

      for (String entry : appLocations) {
        // Make sure we can read the classpath files (e.g. Maven jars) and directories
        appPerms.add(new FilePermission(entry, "read"));
        if (!entry.endsWith(".jar")) {
          appPerms.add(new FilePermission(entry + "/-", "read"));
        }
      }

      // Files and directories the app will access
      appPerms.add(new FilePermission(workDir + "/.vertx", "read,write,delete"));
      appPerms.add(new FilePermission(workDir + "/.vertx/-", "read,write,delete"));
      appPerms.add(new FilePermission(workDir + "/conf/-", "read"));
      appPerms.add(new FilePermission(workDir + "/logs/-", "read,write"));
      appPerms.add(new FilePermission(tempDir, "read,write"));
      // Work-around for the fact Vert.x always checks filesystem before loading classpath resources
      appPerms.add(new FilePermission(workDir + "/static/-", "read"));

      // Accept connections on any dynamic port (this is different from listening on the port)
      appPerms.add(new SocketPermission("*:1024-", "accept"));

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
      appPerms.add(new FilePermission("/etc/resolv.conf", "read"));

      return appPerms;
    }
    if (debug) {
      System.out.println("Returning no permissions for code source: " + path);
    }
    return new Permissions();
  }
}
