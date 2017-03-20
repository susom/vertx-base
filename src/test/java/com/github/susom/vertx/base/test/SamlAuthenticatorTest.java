/*
 * Copyright 2017 The Board of Trustees of The Leland Stanford Junior University.
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

import com.github.susom.vertx.base.SamlAuthenticator;
import java.util.Arrays;
import org.junit.Test;
import org.pac4j.saml.profile.SAML2Profile;

import static org.junit.Assert.assertEquals;

/**
 * Unit tests for the SamlAuthenticator class.
 *
 * @author garricko
 */
public class SamlAuthenticatorTest {
  @Test
  public void readAuthorityAsList() {
    SAML2Profile profile = new SAML2Profile();
    profile.addAttribute("foo", Arrays.asList("bar:bozo", "barbie:ken", "foo"));
    profile.addAttribute("bar", Arrays.asList("bob"));
    assertEquals(Arrays.asList("baz:bozo", "bazbie:ken"), SamlAuthenticator.readAuthorityAsList(profile, new String[] {"noexist", "foo(bar->baz)", "bar"}));
  }
}
