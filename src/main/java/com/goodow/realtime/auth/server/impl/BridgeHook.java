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

import com.google.inject.Inject;

import org.vertx.java.core.AsyncResult;
import org.vertx.java.core.Handler;
import org.vertx.java.core.Vertx;
import org.vertx.java.core.eventbus.EventBus;
import org.vertx.java.core.eventbus.Message;
import org.vertx.java.core.impl.DefaultFutureResult;
import org.vertx.java.core.json.JsonArray;
import org.vertx.java.core.json.JsonObject;
import org.vertx.java.core.logging.Logger;
import org.vertx.java.core.sockjs.EventBusBridgeHook;
import org.vertx.java.core.sockjs.SockJSSocket;
import org.vertx.java.platform.Container;

import java.util.HashMap;
import java.util.Map;

import io.vertx.java.redis.RedisClient;

public class BridgeHook implements EventBusBridgeHook {
  private static final String DEFAULT_STORE_ADDRESS = "realtime.store";
  private static final String DEFAULT_AUTH_ADDRESS = "realtime.auth";
  private static final long REPLY_TIMEOUT = 1 * 1000;
  private final EventBus eb;
  private final Logger logger;
  @Inject private RedisClient redis;
  private final String authoriseAddress;
  private final String storeAddress;
  private final Map<String, String> connections = new HashMap<String, String>();
  private final Map<String, String> sidToAccessToken = new HashMap<String, String>();

  @Inject
  public BridgeHook(Vertx vertx, Container container) {
    this.eb = vertx.eventBus();
    JsonObject config = container.config();
    authoriseAddress = config.getString("address", DEFAULT_AUTH_ADDRESS) + ".authorise";
    storeAddress = config.getString("store_address", DEFAULT_STORE_ADDRESS);
    logger = container.logger();

    eb.registerHandler(storeAddress + ".presence", new Handler<Message<JsonObject>>() {
      @Override
      public void handle(final Message<JsonObject> msg) {
        String docId = msg.body().getString("id");
        redis.smembers(getSessionsKey(docId), new Handler<Message<JsonObject>>() {
          @Override
          public void handle(Message<JsonObject> reply) {
            JsonObject body = reply.body();
            if (!"ok".equals(body.getString("status"))) {
              logger.error(body.getString("message"));
              msg.fail(-1, body.getString("message"));
              return;
            }
            JsonArray sessions = body.getArray("value");
          }
        });
      }
    });
  }

  @Override
  public boolean handleAuthorise(JsonObject message, String accessToken,
      final Handler<AsyncResult<Boolean>> handler) {
    eb.sendWithTimeout(authoriseAddress, message.putString(AuthHandler.ACCESS_TOKEN, accessToken),
        REPLY_TIMEOUT, new Handler<AsyncResult<Message<JsonObject>>>() {
          @Override
          public void handle(AsyncResult<Message<JsonObject>> ar) {
            if (ar.failed()) {
              handler.handle(new DefaultFutureResult<Boolean>(ar.cause()));
              return;
            }
            boolean authed = "ok".equals(ar.result().body().getString("status"));
            handler.handle(new DefaultFutureResult<Boolean>(authed));
          }
        });
    return true;
  }

  @Override
  public void handlePostRegister(SockJSSocket sock, String address) {
    publishPresence(address, sock, true);
  }

  @Override
  public boolean handlePreRegister(SockJSSocket sock, String address) {
    return true;
  }

  @Override
  public boolean handleSendOrPub(SockJSSocket sock, boolean send, JsonObject msg,
      final String address) {
    if (!connections.containsKey(sock.writeHandlerID())) {
      String sid = msg.getString("sid");
      connections.put(sock.writeHandlerID(), sid);
      sidToAccessToken.put(sid, msg.getString(AuthHandler.ACCESS_TOKEN));
    }
    return true;
  }

  @Override
  public void handleSocketClosed(SockJSSocket sock) {
    String sid = connections.remove(sock.writeHandlerID());
    sidToAccessToken.remove(sid);
  }

  @Override
  public boolean handleSocketCreated(SockJSSocket sock) {
    return true;
  }

  @Override
  public boolean handleUnregister(SockJSSocket sock, String address) {
    publishPresence(address, sock, false);
    return true;
  }

  private String getDocId(String address) {
    return address.substring((storeAddress + ":").length());
  }

  private String getSessionsKey(String docId) {
    return storeAddress + ":" + docId + ":sessions";
  }

  private void publishPresence(final String address, SockJSSocket sock, final boolean online) {
    if (!address.startsWith(storeAddress + ":")) {
      return;
    }
    final String sid = connections.get(sock.writeHandlerID());
    final String accessToken = sidToAccessToken.get(sid);
    if (sid == null || accessToken == null) {
      return;
    }
    Handler<Message<JsonObject>> handler = new Handler<Message<JsonObject>>() {
      @Override
      public void handle(Message<JsonObject> reply) {
        JsonObject body = reply.body();
        if (!"ok".equals(body.getString("status"))) {
          logger.error(body.getString("message"));
          return;
        }
        if (body.getInteger("value") != 1) {
          return;
        }
        eb.sendWithTimeout(authoriseAddress, new JsonObject().putString(AuthHandler.ACCESS_TOKEN,
            accessToken), REPLY_TIMEOUT, new Handler<AsyncResult<Message<JsonObject>>>() {
          @Override
          public void handle(AsyncResult<Message<JsonObject>> ar) {
            if (ar.failed()) {
              logger.error("", ar.cause());
              return;
            }
            JsonObject userInfo = ar.result().body();
            boolean authed = "ok".equals(userInfo.getString("status"));
            if (authed) {
              String presenceAddress = storeAddress + ".presence:" + getDocId(address);
              eb.publish(presenceAddress, userInfo.getObject("value")
                  .putBoolean("isJoined", online).putString("sessionId", sid));
            }
          }
        });
      }
    };
    String sessionsKey = getSessionsKey(getDocId(address));
    if (online) {
      redis.sadd(sessionsKey, sid, handler);
    } else {
      redis.srem(sessionsKey, sid, handler);
    }
  }
}