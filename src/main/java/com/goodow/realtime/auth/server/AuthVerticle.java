/*
 * Copyright 2014 Goodow.com
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package com.goodow.realtime.auth.server;

import com.goodow.realtime.auth.server.impl.AuthHandler;
import com.goodow.realtime.auth.server.impl.ChannelHandler;

import com.alienos.guice.GuiceVerticleHelper;
import com.alienos.guice.GuiceVertxBinding;
import com.google.inject.Inject;

import org.vertx.java.busmods.BusModBase;
import org.vertx.java.core.AsyncResult;
import org.vertx.java.core.Future;
import org.vertx.java.core.Handler;
import org.vertx.java.core.impl.CountingCompletionHandler;
import org.vertx.java.core.impl.VertxInternal;

@GuiceVertxBinding(modules = {AuthModule.class})
public class AuthVerticle extends BusModBase {
  @Inject private AuthHandler authHandler;
  @Inject private ChannelHandler channelHandler;

  @Override
  public void start(final Future<Void> startedResult) {
    GuiceVerticleHelper.inject(this, vertx, container);
    super.start();

    final CountingCompletionHandler<Void> countDownLatch =
        new CountingCompletionHandler<Void>((VertxInternal) vertx);
    countDownLatch.setHandler(new Handler<AsyncResult<Void>>() {
      @Override
      public void handle(AsyncResult<Void> ar) {
        if (ar.failed()) {
          startedResult.setFailure(ar.cause());
        } else if (ar.succeeded()) {
          startedResult.setResult(null);
        }
      }
    });
    authHandler.start(countDownLatch);
    channelHandler.start(countDownLatch);
  }
}