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

import com.goodow.realtime.auth.server.impl.BridgeHook;
import com.goodow.realtime.channel.util.IdGenerator;

import com.alienos.guice.VertxModule;
import com.google.inject.AbstractModule;
import com.google.inject.Provides;
import com.google.inject.Singleton;

import org.vertx.java.core.Vertx;
import org.vertx.java.core.sockjs.EventBusBridgeHook;
import org.vertx.java.platform.Container;

import java.security.SecureRandom;
import java.util.Random;

import io.vertx.java.redis.RedisClient;

public class AuthModule extends AbstractModule implements VertxModule {
  private Vertx vertx;
  private Container container;

  @Override
  public void setContainer(Container container) {
    this.container = container;
  }

  @Override
  public void setVertx(Vertx vertx) {
    this.vertx = vertx;
  }

  @Override
  protected void configure() {
    bind(Random.class).to(SecureRandom.class);
    bind(EventBusBridgeHook.class).to(BridgeHook.class);
  }

  @Provides
  @Singleton
  IdGenerator provideIdGenerator(Random random) {
    return new IdGenerator(random);
  }

  @Provides
  @Singleton
  RedisClient provideRedisClient() {
    RedisClient redis =
        new RedisClient(vertx.eventBus(), container.config().getString("redis_address",
            "realtime.redis"));
    return redis;
  }
}