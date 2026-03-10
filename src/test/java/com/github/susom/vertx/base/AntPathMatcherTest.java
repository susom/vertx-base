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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(JUnit4.class)
public class AntPathMatcherTest {

  // -----------------------------------------------------------------------
  // Exact (no wildcards)
  // -----------------------------------------------------------------------

  @Test
  public void exactMatch() {
    assertTrue(AntPathMatcher.match("foo/bar.txt", "foo/bar.txt"));
  }

  @Test
  public void exactMatchFails() {
    assertFalse(AntPathMatcher.match("foo/bar.txt", "foo/baz.txt"));
  }

  @Test
  public void exactMatchEmptyStrings() {
    assertTrue(AntPathMatcher.match("", ""));
  }

  // -----------------------------------------------------------------------
  // '?' wildcard – matches exactly one non-'/' character
  // -----------------------------------------------------------------------

  @Test
  public void questionMarkMatchesSingleChar() {
    assertTrue(AntPathMatcher.match("foo/ba?.txt", "foo/bar.txt"));
    assertTrue(AntPathMatcher.match("foo/ba?.txt", "foo/baz.txt"));
  }

  @Test
  public void questionMarkDoesNotMatchSlash() {
    assertFalse(AntPathMatcher.match("foo/ba?.txt", "foo/ba/.txt"));
  }

  @Test
  public void questionMarkDoesNotMatchZeroChars() {
    assertFalse(AntPathMatcher.match("foo/ba?.txt", "foo/ba.txt"));
  }

  @Test
  public void questionMarkDoesNotMatchTwoChars() {
    assertFalse(AntPathMatcher.match("foo/ba?.txt", "foo/barr.txt"));
  }

  @Test
  public void multipleQuestionMarks() {
    assertTrue(AntPathMatcher.match("?oo/?ar", "foo/bar"));
    assertFalse(AntPathMatcher.match("?oo/?ar", "fo/bar"));
  }

  // -----------------------------------------------------------------------
  // '*' wildcard – matches zero or more chars within a single segment
  // -----------------------------------------------------------------------

  @Test
  public void singleStarMatchesSegment() {
    assertTrue(AntPathMatcher.match("foo/*.txt", "foo/bar.txt"));
    assertTrue(AntPathMatcher.match("foo/*.txt", "foo/.txt"));      // zero chars
    assertTrue(AntPathMatcher.match("foo/*.txt", "foo/longname.txt"));
  }

  @Test
  public void singleStarDoesNotCrossSlash() {
    assertFalse(AntPathMatcher.match("foo/*.txt", "foo/bar/baz.txt"));
  }

  @Test
  public void singleStarAlone() {
    assertTrue(AntPathMatcher.match("*", "anything"));
    assertFalse(AntPathMatcher.match("*", "any/thing"));
  }

  @Test
  public void singleStarPrefixSuffix() {
    assertTrue(AntPathMatcher.match("*.txt", "file.txt"));
    assertTrue(AntPathMatcher.match("file.*", "file.txt"));
    assertFalse(AntPathMatcher.match("*.txt", "dir/file.txt"));
  }

  @Test
  public void singleStarMatchesEmptySegment() {
    // pattern "foo/*" should match "foo/" (empty trailing segment)
    assertTrue(AntPathMatcher.match("foo/*", "foo/"));
  }

  // -----------------------------------------------------------------------
  // '**' wildcard – matches zero or more path segments
  // -----------------------------------------------------------------------

  @Test
  public void doubleStarMatchesMultipleSegments() {
    assertTrue(AntPathMatcher.match("**/*", "foo/bar.txt"));
    assertTrue(AntPathMatcher.match("**/*", "a/b/c/d.txt"));
  }

  @Test
  public void doubleStarAtEnd() {
    assertTrue(AntPathMatcher.match("foo/**", "foo/bar"));
    assertTrue(AntPathMatcher.match("foo/**", "foo/bar/baz"));
    assertTrue(AntPathMatcher.match("foo/**", "foo/"));
  }

  @Test
  public void doubleStarMatchesZeroSegments() {
    // "**/*" should match a plain filename with no directory prefix
    assertTrue(AntPathMatcher.match("**/*", "file.txt"));
  }

  @Test
  public void doubleStarInMiddle() {
    assertTrue(AntPathMatcher.match("foo/**/bar.txt", "foo/bar.txt"));
    assertTrue(AntPathMatcher.match("foo/**/bar.txt", "foo/x/bar.txt"));
    assertTrue(AntPathMatcher.match("foo/**/bar.txt", "foo/x/y/z/bar.txt"));
    assertFalse(AntPathMatcher.match("foo/**/bar.txt", "foo/x/baz.txt"));
  }

  @Test
  public void doubleStarOnly() {
    assertTrue(AntPathMatcher.match("**", "anything"));
    assertTrue(AntPathMatcher.match("**", "any/thing"));
    assertTrue(AntPathMatcher.match("**", "a/b/c"));
  }

  @Test
  public void doubleStarWithExtension() {
    assertTrue(AntPathMatcher.match("**/*.txt", "foo/bar.txt"));
    assertTrue(AntPathMatcher.match("**/*.txt", "a/b/c/file.txt"));
    assertFalse(AntPathMatcher.match("**/*.txt", "foo/bar.html"));
  }

  // -----------------------------------------------------------------------
  // Realistic classpath-scan patterns (the primary use case)
  // -----------------------------------------------------------------------

  @Test
  public void typicalClasspathPattern() {
    // The default pattern used by addDir() is "**/*"
    assertTrue(AntPathMatcher.match("**/*", "index.html"));
    assertTrue(AntPathMatcher.match("**/*", "css/style.css"));
    assertTrue(AntPathMatcher.match("**/*", "js/vendor/jquery.min.js"));
  }

  @Test
  public void specificSubdirectoryPattern() {
    assertTrue(AntPathMatcher.match("css/*", "css/style.css"));
    assertFalse(AntPathMatcher.match("css/*", "js/style.css"));
    assertFalse(AntPathMatcher.match("css/*", "css/sub/style.css"));
  }

  @Test
  public void noMatchOnMismatchedExtension() {
    assertFalse(AntPathMatcher.match("**/*.js", "foo/bar.css"));
  }

  @Test
  public void leadingDoubleStarSlash() {
    // "**/" prefix should match files at any depth
    assertTrue(AntPathMatcher.match("**/foo.txt", "foo.txt"));
    assertTrue(AntPathMatcher.match("**/foo.txt", "a/foo.txt"));
    assertTrue(AntPathMatcher.match("**/foo.txt", "a/b/c/foo.txt"));
    assertFalse(AntPathMatcher.match("**/foo.txt", "a/b/bar.txt"));
  }
}
