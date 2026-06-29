#include "Store.hpp"

#include <chen/db/mysql.h>
#include <chen/db/redis.h>
#include <chen/log/log.h>
#include <chen/util/encryptor_util.h>
#include <chen/util/json_util.h>
#include <chen/util/random_util.h>
#include <chen/util/string_util.h>

#include "auth/data/oauth_clients_info.h"
#include "auth/data/oauth_users_info.h"
#include "util.h"

namespace auth {

static chen::Logger::ptr logger = LOG_NAME("auth");

Json::Value UserStore::findByUsername(const std::string& username) {
    auto db = auth::GetDB();
    if (!db) {
        ERROR(logger) << "UserStore: get mysql conn failed";
        return Json::nullValue;
    }

    auto info = auth::data::OauthUsersInfoDao::QueryByUsername(username, db);
    if (!info) {
        WARN(logger) << "user not found for username=" << username;
        return Json::nullValue;
    }

    Json::Value user;
    user["id"] = info->getId();
    user["username"] = info->getUsername();
    user["email"] = info->getEmail();
    user["password_hash"] = info->getPasswordHash();
    user["display_name"] = info->getDisplayName();
    user["avatar_url"] = info->getAvatarUrl();
    user["email_verified"] = info->getEmailVerified();
    user["enabled"] = info->getEnabled();
    return user;
}

Json::Value UserStore::verifyPassword(const std::string& username, const std::string& password) {
    Json::Value user = findByUsername(username);
    if (user.isNull()) {
        WARN(logger) << "user not found for username=" << username;
        return Json::nullValue;
    }

    std::string hash = user["password_hash"].asString();
    if (!chen::EncryptorUtil::BCryptVerify(password, hash)) {
        WARN(logger) << "password mismatch for user=" << username;
        return Json::nullValue;
    }

    user.removeMember("password_hash");
    return user;
}

Json::Value ClientStore::findByClientId(const std::string& clientId) {
    auto db = auth::GetDB();
    if (!db) {
        ERROR(logger) << "ClientStore: get mysql conn failed";
        return Json::nullValue;
    }

    auto info = auth::data::OauthClientsInfoDao::QueryByClientId(clientId, db);
    if (!info) {
        WARN(logger) << "client not found for client_id=" << clientId;
        return Json::nullValue;
    }

    Json::Value client;
    client["id"] = info->getId();
    client["client_id"] = info->getClientId();
    client["client_secret_hash"] = info->getClientSecretHash();
    client["client_name"] = info->getClientName();
    client["redirect_uris"] = info->getRedirectUris();
    client["grant_types"] = info->getGrantTypes();
    client["allowed_scopes"] = info->getAllowedScopes();
    client["enabled"] = info->getEnabled();
    return client;
}

bool ClientStore::validateRedirectUri(const std::string& clientId, const std::string& redirectUri) {
    Json::Value client = findByClientId(clientId);
    if (client.isNull()) {
        return false;
    }

    Json::Value uris;
    if (!chen::JsonUtil::FromString(uris, client["redirect_uris"].asString())) {
        ERROR(logger) << "parse redirect_uris JSON failed for client=" << clientId;
        return false;
    }
    if (!uris.isArray()) {
        return false;
    }

    for (auto& u : uris) {
        if (u.asString() == redirectUri) {
            return true;
        }
    }
    return false;
}

bool AuthCodeStore::save(const std::string& code, const std::string& data, int ttl) {
    auto rds = GetRedis();
    if (!rds) {
        ERROR(logger) << "AuthCodeStore: get redis conn failed";
        return false;
    }

    auto reply = rds->cmd("SETEX %s %d %s", code.c_str(), ttl, data.c_str());
    return reply && reply->type == REDIS_REPLY_STATUS && strcasecmp(reply->str, "OK") == 0;
}

Json::Value AuthCodeStore::consume(const std::string& code) {
    auto rds = GetRedis();
    if (!rds) {
        ERROR(logger) << "AuthCodeStore: get redis conn failed";
        return Json::nullValue;
    }

    std::string lua = "local v = redis.call('GET', KEYS[1])\n"
                      "if v then redis.call('DEL', KEYS[1]) end\n"
                      "return v";

    auto reply = rds->cmd("EVAL %s 1 %s", lua.c_str(), code.c_str());
    if (!reply || reply->type != REDIS_REPLY_STRING) {
        return Json::nullValue;
    }

    Json::Value data;
    if (!chen::JsonUtil::FromString(data, reply->str)) {
        ERROR(logger) << "AuthCodeStore: parse stored JSON failed";
        return Json::nullValue;
    }
    return data;
}

bool RefreshTokenStore::save(const std::string& token, const std::string& data, int ttl) {
    auto rds = GetRedis();
    if (!rds) {
        ERROR(logger) << "RefreshTokenStore: get redis conn failed";
        return false;
    }

    auto reply = rds->cmd("SETEX %s %d %s", token.c_str(), ttl, data.c_str());
    return reply && reply->type == REDIS_REPLY_STATUS && strcasecmp(reply->str, "OK") == 0;
}

Json::Value RefreshTokenStore::consume(const std::string& token) {
    auto rds = GetRedis();
    if (!rds) {
        ERROR(logger) << "RefreshTokenStore: get redis conn failed";
        return Json::nullValue;
    }

    std::string lua = "local v = redis.call('GET', KEYS[1])\n"
                      "if v then redis.call('DEL', KEYS[1]) end\n"
                      "return v";

    auto reply = rds->cmd("EVAL %s 1 %s", lua.c_str(), token.c_str());
    if (!reply || reply->type != REDIS_REPLY_STRING) {
        return Json::nullValue;
    }

    Json::Value data;
    if (!chen::JsonUtil::FromString(data, reply->str)) {
        ERROR(logger) << "RefreshTokenStore: parse stored JSON failed";
        return Json::nullValue;
    }
    return data;
}

void RefreshTokenStore::revoke(const std::string& token) {
    auto rds = GetRedis();
    if (!rds) {
        ERROR(logger) << "RefreshTokenStore: get redis conn failed";
        return;
    }
    rds->cmd("DEL %s", token.c_str());
}

std::string SessionStore::createSession(int64_t userId, const std::string& username, int ttl) {
    auto rds = GetRedis();
    if (!rds) {
        ERROR(logger) << "SessionStore: get redis conn failed";
        return "";
    }

    std::string sid = chen::StringUtil::ToLower(chen::StringUtil::HexEncode(chen::RandomUtil::RandBytes(32)));

    Json::Value data;
    data["userId"] = userId;
    data["username"] = username;
    std::string val = chen::JsonUtil::ToString(data);

    auto reply = rds->cmd("SETEX sess:%s %d %s", sid.c_str(), ttl, val.c_str());
    if (!reply || reply->type != REDIS_REPLY_STATUS || strcasecmp(reply->str, "OK") != 0) {
        return "";
    }
    return sid;
}

Json::Value SessionStore::getSession(const std::string& sessionId) {
    auto rds = GetRedis();
    if (!rds) {
        ERROR(logger) << "SessionStore: get redis conn failed";
        return Json::nullValue;
    }

    auto reply = rds->cmd("GET sess:%s", sessionId.c_str());
    if (!reply || reply->type != REDIS_REPLY_STRING) {
        return Json::nullValue;
    }

    Json::Value data;
    if (!chen::JsonUtil::FromString(data, reply->str)) {
        return Json::nullValue;
    }
    return data;
}

void SessionStore::destroySession(const std::string& sessionId) {
    auto rds = GetRedis();
    if (!rds) {
        ERROR(logger) << "SessionStore: get redis conn failed";
        return;
    }
    rds->cmd("DEL sess:%s", sessionId.c_str());
}

} // namespace auth
