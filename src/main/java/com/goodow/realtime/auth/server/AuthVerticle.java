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

import org.vertx.java.busmods.BusModBase;
import org.vertx.java.core.AsyncResult;
import org.vertx.java.core.Future;
import org.vertx.java.core.Handler;
import org.vertx.java.core.eventbus.Message;
import org.vertx.java.core.eventbus.ReplyException;
import org.vertx.java.core.impl.CountingCompletionHandler;
import org.vertx.java.core.impl.VertxInternal;
import org.vertx.java.core.json.JsonArray;
import org.vertx.java.core.json.JsonObject;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class AuthVerticle extends BusModBase {
  private static final class LoginInfo {
    final long timerID;
    final String sessionID;

    private LoginInfo(long timerID, String sessionID) {
      this.timerID = timerID;
      this.sessionID = sessionID;
    }
  }

  private static final long REPLY_TIMEOUT = 1 * 1000;
  public static final String DEFAULT_ADDRESS = "realtime.auth";
  private static final long DEFAULT_SESSION_TIMEOUT = 30 * 60 * 1000;
  private static final String DEFAULT_USER_INDEX = "realtime";
  private static final String DEFAULT_USER_TYPE = "users";

  private String address;
  private long sessionTimeout;
  private String persistorAddress;
  private String userIndex;
  private String userType;
  protected final Map<String, String> sessions = new HashMap<String, String>();
  protected final Map<String, LoginInfo> logins = new HashMap<String, LoginInfo>();

  @Override
  public void start(final Future<Void> startedResult) {
    super.start();
    address = getOptionalStringConfig("address", DEFAULT_ADDRESS);
    sessionTimeout = getOptionalLongConfig("session_timeout", DEFAULT_SESSION_TIMEOUT);
    persistorAddress = getOptionalStringConfig("persistor_address", "realtime.search");
    userIndex = getOptionalStringConfig("user_index", DEFAULT_USER_INDEX);
    userType = getOptionalStringConfig("user_type", DEFAULT_USER_TYPE);

    final CountingCompletionHandler<Void> countDownLatch =
        new CountingCompletionHandler<Void>((VertxInternal) vertx, 3);
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

    eb.registerHandler(address + ".login", new Handler<Message<JsonObject>>() {
      @Override
      public void handle(Message<JsonObject> message) {
        doLogin(message);
      }
    }, doneHandler);

    eb.registerHandler(address + ".logout", new Handler<Message<JsonObject>>() {
      @Override
      public void handle(Message<JsonObject> message) {
        doLogout(message);
      }
    }, doneHandler);

    eb.registerHandler(address + ".authorise", new Handler<Message<JsonObject>>() {
      @Override
      public void handle(Message<JsonObject> message) {
        doAuthorise(message);
      }
    }, doneHandler);
  }

  protected void doAuthorise(Message<JsonObject> message) {
    String sessionID = getMandatoryString("sessionID", message);
    if (sessionID == null) {
      return;
    }
    String userId = sessions.get(sessionID);

    // In this basic auth manager we don't do any resource specific authorisation
    // The user is always authorised if they are logged in

    if (userId != null) {
      JsonObject reply = new JsonObject().putString("userId", userId);
      sendOK(message, reply);
    } else {
      sendStatus("denied", message);
    }
  }

  protected void doLogout(final Message<JsonObject> message) {
    final String sessionID = getMandatoryString("sessionID", message);
    if (sessionID != null) {
      if (logout(sessionID)) {
        sendOK(message);
      } else {
        super.sendError(message, "Not logged in");
      }
    }
  }

  protected boolean logout(String sessionID) {
    String userId = sessions.remove(sessionID);
    if (userId != null) {
      LoginInfo info = logins.remove(userId);
      vertx.cancelTimer(info.timerID);
      return true;
    } else {
      return false;
    }
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

            // Check if already logged in, if so logout of the old session
            LoginInfo info = logins.get(userId);
            if (info != null) {
              logout(info.sessionID);
            }

            // Found
            final String sessionID = UUID.randomUUID().toString();
            long timerID = vertx.setTimer(sessionTimeout, new Handler<Long>() {
              @Override
              public void handle(Long timerID) {
                sessions.remove(sessionID);
                logins.remove(userId);
              }
            });
            sessions.put(sessionID, userId);
            logins.put(userId, new LoginInfo(timerID, sessionID));
            JsonObject jsonReply = new JsonObject().putString("sessionID", sessionID);
            sendOK(message, jsonReply);
          }
        });
  }
}