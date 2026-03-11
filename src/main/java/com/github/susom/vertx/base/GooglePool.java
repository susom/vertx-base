/*
 * Copyright 2026 The Board of Trustees of The Leland Stanford Junior University.
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
import com.github.susom.database.DatabaseException;
import com.github.susom.database.DatabaseProvider.Pool;
import com.github.susom.database.Flavor;
import com.google.auth.oauth2.GoogleCredentials;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import com.zaxxer.hikari.util.Credentials;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Create a Hikari connection pool that supports IAM authentication for Google Cloud SQL. The
 * pool will automatically refresh the IAM token as needed. This is meant to be a drop in
 * replacement for the default pool provided by the susom/database library.
 */
public class GooglePool {
  private static final Logger log = LoggerFactory.getLogger(GooglePool.class);
  private static final AtomicInteger poolNameCounter = new AtomicInteger(1);

  public static Pool createPool(Config config) {
    String url = config.getString("database.url");
    if (url == null) {
      throw new DatabaseException("You must provide database.url");
    }

    String user = config.getString("database.user");
    String password = config.getString("database.password");

    boolean useIamAuth = (user != null && user.contains("@")) || password == null || password.isEmpty() || password.equals("iam");
    if (useIamAuth && (user == null || user.isBlank())) {
      throw new DatabaseException("You must provide database.user when using IAM authentication (password is null, empty, or 'iam')");
    }

    HikariConfig hc = new HikariConfig();
    // If we don't provide a pool name it will automatically generate one, but
    // the way it does that requires PropertyPermission("*", "read,write") and
    // will fail if the security sandbox is enabled
    hc.setPoolName(config.getString("database.pool.name", "GooglePool-" + poolNameCounter.getAndIncrement()));
    hc.setJdbcUrl(url);
    String driverClassName = config.getString("database.driver.class", Flavor.driverForJdbcUrl(url));
    hc.setDriverClassName(driverClassName);
    if (useIamAuth) {
      hc.addDataSourceProperty("ssl", "true");
      hc.addDataSourceProperty("sslmode", "require");

      // Create and scope the application default credentials once, then reuse them
      final GoogleCredentials scopedCredentials;
      try {
        GoogleCredentials credentials = GoogleCredentials.getApplicationDefault();
        // Narrow the authority to what we need
        scopedCredentials = credentials.createScoped("https://www.googleapis.com/auth/sqlservice.login");
      } catch (IOException err) {
        throw new RuntimeException("Unable to obtain Google credential", err);
      }

      hc.setCredentialsProvider(() -> {
        try {
          // Refresh only if the token is expired, to avoid unnecessary refreshes
          scopedCredentials.refreshIfExpired();
        } catch (IOException e) {
          throw new RuntimeException("Error refreshing the scoped credential", e);
        }

        return new Credentials(user, scopedCredentials.getAccessToken().getTokenValue());
      });
    } else {
      hc.setUsername(user);
      hc.setPassword(password);
    }
    int poolSize = config.getInteger("database.pool.size", 10);
    hc.setMaximumPoolSize(poolSize);
    hc.setAutoCommit(false);
    hc.setConnectionInitSql(config.getString("database.conn.initsql"));

    HikariDataSource ds = new HikariDataSource(hc);

    Flavor flavor;
    String flavorString = config.getString("database.flavor");
    if (flavorString != null) {
      flavor = Flavor.valueOf(flavorString);
    } else {
      flavor = Flavor.fromJdbcUrl(url);
    }

    String iamPart = useIamAuth ? " IAM" : "";
    log.debug("Created '{}'{} connection pool of size {} using driver {}", flavor, iamPart, poolSize, driverClassName);

    return new Pool(ds, poolSize, flavor, ds);
  }
}
