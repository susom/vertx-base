/*
 * Copyright 2024 The Board of Trustees of The Leland Stanford Junior University.
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
package com.github.susom.vertx.base.test;

import com.github.susom.vertx.base.PortInfo;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.junit.Assert.*;

@RunWith(JUnit4.class)
public class PortInfoTest {

  @Test
  public void testPortInfo() {
    PortInfo portInfo = new PortInfo("https", "example.com", 443);
    assertEquals("https", portInfo.proto());
    assertEquals("example.com", portInfo.host());
    assertEquals(443, portInfo.port());

    // Test parsing with https default port
    portInfo = PortInfo.parseUrl("https://example.com");
    assertEquals("https", portInfo.proto());
    assertEquals("example.com", portInfo.host());
    assertEquals(443, portInfo.port());

    // Test parsing with http default port
    portInfo = PortInfo.parseUrl("http://example.com/");
    assertEquals("http", portInfo.proto());
    assertEquals("example.com", portInfo.host());
    assertEquals(80, portInfo.port());

    // Test parsing with explicit port
    portInfo = PortInfo.parseUrl("https://example.com:8080/foo");
    assertEquals("https", portInfo.proto());
    assertEquals("example.com", portInfo.host());
    assertEquals(8080, portInfo.port());

    // Check null
    assertNull(PortInfo.parseUrl(null));

    // Disallow protocols other than http/https
    try {
      PortInfo.parseUrl("ftp://example.com");
      fail("Should have thrown an exception for invalid protocol");
    } catch (RuntimeException e) {
      assertEquals("Invalid protocol for url: ftp://example.com", e.getMessage());
    }
  }
}
