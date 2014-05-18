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
package com.goodow.realtime.auth.server.impl;

import com.goodow.realtime.channel.server.ChannelBridge;

import com.google.inject.Inject;

import org.vertx.java.core.Vertx;
import org.vertx.java.core.impl.CountingCompletionHandler;
import org.vertx.java.core.sockjs.EventBusBridgeHook;
import org.vertx.java.platform.Container;

public class ChannelHandler {
  @Inject private Vertx vertx;
  @Inject private Container container;
  @Inject private EventBusBridgeHook hook;

  public void start(final CountingCompletionHandler<Void> countDownLatch) {
    new ChannelBridge(vertx, container.config()).setHook(hook).bridge(countDownLatch);
  }
}
