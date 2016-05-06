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

import java.util.function.Supplier;
import org.apache.commons.lang3.concurrent.ConcurrentException;
import org.apache.commons.lang3.concurrent.LazyInitializer;

/**
 * An interface for lazy initialization of Suppliers. This is useful because
 * you can declare you supplier early and pass this wrapper instance around,
 * and the underlying resources will not be allocated until needed.
 *
 * @author garricko
 */
public interface Lazy<T> extends Supplier<T> {
  static <L> Lazy<L> initializer(Supplier<L> supplier) {
    return new Lazy<L>() {
      LazyInitializer<L> lazy = new LazyInitializer<L>() {
        @Override
        protected L initialize() throws ConcurrentException {
          return supplier.get();
        }
      };

      @Override
      public L get() {
        try {
          return lazy.get();
        } catch (ConcurrentException e) {
          throw new RuntimeException(e);
        }
      }
    };
  }
}
