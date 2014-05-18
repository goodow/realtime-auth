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

import com.goodow.realtime.channel.util.IdGenerator;

import com.google.inject.Inject;

import org.vertx.java.busmods.BusModBase;
import org.vertx.java.core.AsyncResult;
import org.vertx.java.core.Handler;
import org.vertx.java.core.Vertx;
import org.vertx.java.core.eventbus.Message;
import org.vertx.java.core.eventbus.ReplyException;
import org.vertx.java.core.impl.CountingCompletionHandler;
import org.vertx.java.core.json.JsonArray;
import org.vertx.java.core.json.JsonObject;
import org.vertx.java.platform.Container;

import io.vertx.java.redis.RedisClient;

public class AuthHandler extends BusModBase {
  public static final String ACCESS_TOKEN = "access_token";
  private static final long REPLY_TIMEOUT = 1 * 1000;
  public static final String DEFAULT_ADDRESS = "realtime.auth";
  private static final long DEFAULT_SESSION_TIMEOUT = 30 * 60 * 1000;
  private static final String DEFAULT_USER_INDEX = "realtime";
  private static final String DEFAULT_USER_TYPE = "users";

  @Inject private RedisClient redis;
  @Inject private IdGenerator idGenerator;
  @Inject private Anonymous anonymous;
  private String address;
  private long sessionTimeout;
  private String persistorAddress;
  private String userIndex;
  private String userType;

  @Inject
  public AuthHandler(Vertx vertx, Container container) {
    eb = vertx.eventBus();
    logger = container.logger();
    config = container.config();
  }

  public void start(final CountingCompletionHandler<Void> countDownLatch) {
    address = config.getString("address", DEFAULT_ADDRESS);
    sessionTimeout = config.getLong("session_timeout", DEFAULT_SESSION_TIMEOUT);
    persistorAddress = config.getString("persistor_address", "realtime.search");
    userIndex = config.getString("user_index", DEFAULT_USER_INDEX);
    userType = config.getString("user_type", DEFAULT_USER_TYPE);

    Handler<AsyncResult<Void>> doneHandler = new Handler<AsyncResult<Void>>() {
      @Override
      public void handle(AsyncResult<Void> ar) {
        if (ar.failed()) {
          countDownLatch.failed(ar.cause());
        } else {
          countDownLatch.complete();
        }
      }
    };

    countDownLatch.incRequired();
    eb.registerHandler(address + ".login", new Handler<Message<JsonObject>>() {
      @Override
      public void handle(Message<JsonObject> message) {
        doLogin(message);
      }
    }, doneHandler);
    countDownLatch.incRequired();
    eb.registerHandler(address + ".logout", new Handler<Message<JsonObject>>() {
      @Override
      public void handle(Message<JsonObject> message) {
        doLogout(message);
      }
    }, doneHandler);
    countDownLatch.incRequired();
    eb.registerHandler(address + ".authorise", new Handler<Message<JsonObject>>() {
      @Override
      public void handle(Message<JsonObject> message) {
        doAuthorise(message);
      }
    }, doneHandler);
  }

  protected void doAuthorise(final Message<JsonObject> message) {
    String accessToken = getMandatoryString(ACCESS_TOKEN, message);
    if (accessToken == null) {
      return;
    }
    redis.hgetall(getAccessTokenKey(accessToken), new Handler<Message<JsonObject>>() {
      @Override
      public void handle(Message<JsonObject> reply) {
        JsonObject body = reply.body();
        if (!"ok".equals(body.getString("status"))) {
          message.fail(-1, body.getString("message"));
          return;
        }
        JsonObject tokenInfo = body.getObject("value");
        if (tokenInfo != null) {
          sendOK(message, tokenInfo);
        } else {
          sendStatus("denied", message);
        }
      }
    });
  }

  protected void doLogout(final Message<JsonObject> message) {
    final String accessToken = getMandatoryString(ACCESS_TOKEN, message);
    if (accessToken != null) {
      logout(accessToken, message);
    }
  }

  protected void logout(String accessToken, final Message<JsonObject> message) {
    redis.del(getAccessTokenKey(accessToken), new Handler<Message<JsonObject>>() {
      @Override
      public void handle(Message<JsonObject> reply) {
        JsonObject body = reply.body();
        if (!"ok".equals(body.getString("status"))) {
          message.fail(-1, body.getString("message"));
          return;
        }
        int removedKeys = body.getInteger("value");
        if (removedKeys == 0) {
          sendError(message, "Not logged in");
        } else {
          sendOK(message);
        }
      }
    });
  }

  private void doLogin(final Message<JsonObject> message) {
    final String userId = getMandatoryString("userId", message);
    if (userId == null) {
      return;
    }
    String token = getMandatoryString("token", message);
    if (token == null) {
      return;
    }

    if (userId.isEmpty()) {
      String displyName = anonymous.getDisplyName();
      JsonObject anonymousUser =
          new JsonObject().putString("userId", anonymous.getUserId()).putString("displyName",
              displyName).putString("color", anonymous.getColor()).putString("photoUrl",
              anonymous.getPhotoUrl(displyName)).putBoolean("isAnonymous", true);
      saveToRedis(message, anonymousUser);
      return;
    }

    JsonObject idFilter =
        new JsonObject().putObject("ids", new JsonObject().putArray("values", new JsonArray()
            .add(userId)));
    JsonObject tokenFilter =
        new JsonObject().putObject("term", new JsonObject().putString("token", token));
    JsonObject filter =
        new JsonObject().putObject("filter", new JsonObject().putArray("and", new JsonArray().add(
            idFilter).add(tokenFilter)));

    JsonObject search =
        new JsonObject().putString("action", "search").putString("_index", userIndex).putString(
            "_type", userType).putObject("source", filter);
    eb.sendWithTimeout(persistorAddress, search, REPLY_TIMEOUT,
        new Handler<AsyncResult<Message<JsonObject>>>() {
          @Override
          public void handle(AsyncResult<Message<JsonObject>> ar) {
            if (ar.failed()) {
              ReplyException cause = (ReplyException) ar.cause();
              logger.error("Failed to execute login query", cause);
              message.fail(cause.failureCode(), "Failed to excecute login: " + cause.getMessage());
              return;
            }
            if (ar.result().body().getObject("hits").getInteger("total") != 1) {
              // Not found
              sendStatus("denied", message);
              return;
            }

            // Found
            JsonObject user =
                ar.result().body().getObject("hits").getArray("hits").<JsonObject> get(0);
            final JsonObject userInfo =
                user.getObject("_source").putString("userId", user.getString("_id"));

            saveToRedis(message, userInfo);
          }
        });
  }

  private String getAccessTokenKey(String accessToken) {
    return "token:" + accessToken;
  }

  private void saveToRedis(final Message<JsonObject> message, final JsonObject userInfo) {
    final String accessToken = idGenerator.next(66);
    redis.hmset(getAccessTokenKey(accessToken), userInfo, new Handler<Message<JsonObject>>() {
      @Override
      public void handle(Message<JsonObject> reply) {
        JsonObject body = reply.body();
        if (!"ok".equals(body.getString("status"))) {
          message.fail(-1, body.getString("message"));
          return;
        }
        redis.pexpire(getAccessTokenKey(accessToken), sessionTimeout,
            new Handler<Message<JsonObject>>() {
              @Override
              public void handle(Message<JsonObject> reply) {
                JsonObject body = reply.body();
                if (!"ok".equals(body.getString("status"))) {
                  message.fail(-1, body.getString("message"));
                  return;
                }
                int success = body.getInteger("value");
                if (success == 0) {
                  sendError(message, "key does not exist or the timeout could not be set");
                } else {
                  sendOK(message, userInfo.putString("access_token", accessToken).putString("sid",
                      idGenerator.next(16)));
                }
              }
            });
      }
    });
  }
}