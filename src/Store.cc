#include "Store.hpp"

#include <chen/db/mysql.h>
#include <chen/db/redis.h>
#include <chen/log/log.h>
#include <chen/util/encryptor_util.h>
#include <chen/util/json_util.h>
#include <chen/util/random_util.h>
#include <chen/util/string_util.h>

namespace auth {

static chen::Logger::ptr logger = LOG_NAME("auth");

Json::Value UserStore::findByUsername(const std::string& username) {
    auto db = chen::MySQLMgr::GetInstance()->get("auth");
    if (!db) {
        ERROR(logger) << "UserStore: get mysql conn failed";
        return Json::nullValue;
    }

    // queryStmt 要求 string 参数为非 const，传一份副本
    std::string param = username;
    auto res = db->queryStmt("SELECT id, username, email, password_hash, display_name, "
                             "avatar_url, email_verified, enabled FROM oauth_users "
                             "WHERE username = ? AND enabled = 1 LIMIT 1",
                             param);
    if (!res || res->getDataCount() == 0) {
        return Json::nullValue;
    }

    res->next();
    Json::Value user;
    user["id"] = res->getInt64(0);
    user["username"] = res->getString(1);
    user["email"] = res->getString(2);
    user["password_hash"] = res->getString(3);
    user["display_name"] = res->getString(4);
    user["avatar_url"] = res->getString(5);
    user["email_verified"] = res->getInt32(6);
    user["enabled"] = res->getInt32(7);
    return user;
}

Json::Value UserStore::verifyPassword(const std::string& username, const std::string& password) {
    Json::Value user = findByUsername(username);
    if (user.isNull()) {
        return Json::nullValue;
    }

    std::string hash = user["password_hash"].asString();
    if (!chen::EncryptorUtil::BCryptVerify(password, hash)) {
        WARN(logger) << "password mismatch for user=" << username;
        return Json::nullValue;
    }

    // 返回前移除密码哈希
    user.removeMember("password_hash");
    return user;
}

Json::Value ClientStore::findByClientId(const std::string& clientId) {
    auto db = chen::MySQLMgr::GetInstance()->get("auth");
    if (!db) {
        ERROR(logger) << "ClientStore: get mysql conn failed";
        return Json::nullValue;
    }

    std::string param = clientId;
    auto res = db->queryStmt("SELECT id, client_id, client_secret_hash, client_name, "
                             "redirect_uris, grant_types, allowed_scopes, enabled "
                             "FROM oauth_clients WHERE client_id = ? AND enabled = 1 LIMIT 1",
                             param);
    if (!res || res->getDataCount() == 0) {
        return Json::nullValue;
    }

    res->next();
    Json::Value client;
    client["id"] = res->getInt64(0);
    client["client_id"] = res->getString(1);
    client["client_secret_hash"] = res->getString(2);
    client["client_name"] = res->getString(3);
    client["redirect_uris"] = res->getString(4);
    client["grant_types"] = res->getString(5);
    client["allowed_scopes"] = res->getString(6);
    client["enabled"] = res->getInt32(7);
    return client;
}

bool ClientStore::validateRedirectUri(const std::string& clientId, const std::string& redirectUri) {
    Json::Value client = findByClientId(clientId);
    if (client.isNull()) {
        return false;
    }

    // redirect_uris 存的是 JSON 数组字符串，如 ["https://a.com/cb","https://b.com/cb"]
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
    auto rds = chen::RedisMgr::GetInstance()->get("auth");
    if (!rds) {
        ERROR(logger) << "AuthCodeStore: get redis conn failed";
        return false;
    }

    auto reply = rds->cmd("SETEX %s %d %s", code.c_str(), ttl, data.c_str());
    return reply && reply->type == REDIS_REPLY_STATUS && strcasecmp(reply->str, "OK") == 0;
}

Json::Value AuthCodeStore::consume(const std::string& code) {
    auto rds = chen::RedisMgr::GetInstance()->get("auth");
    if (!rds) {
        ERROR(logger) << "AuthCodeStore: get redis conn failed";
        return Json::nullValue;
    }

    // Lua 脚本：原子地获取并删除
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
    auto rds = chen::RedisMgr::GetInstance()->get("auth");
    if (!rds) {
        ERROR(logger) << "RefreshTokenStore: get redis conn failed";
        return false;
    }

    auto reply = rds->cmd("SETEX %s %d %s", token.c_str(), ttl, data.c_str());
    return reply && reply->type == REDIS_REPLY_STATUS && strcasecmp(reply->str, "OK") == 0;
}

Json::Value RefreshTokenStore::consume(const std::string& token) {
    auto rds = chen::RedisMgr::GetInstance()->get("auth");
    if (!rds) {
        ERROR(logger) << "RefreshTokenStore: get redis conn failed";
        return Json::nullValue;
    }

    // 同 AuthCodeStore：原子地 GET 后 DEL
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
    auto rds = chen::RedisMgr::GetInstance()->get("auth");
    if (!rds) {
        return;
    }
    rds->cmd("DEL %s", token.c_str());
}

std::string SessionStore::createSession(int64_t userId, const std::string& username, int ttl) {
    auto rds = chen::RedisMgr::GetInstance()->get("auth");
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
    auto rds = chen::RedisMgr::GetInstance()->get("auth");
    if (!rds) {
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
    auto rds = chen::RedisMgr::GetInstance()->get("auth");
    if (!rds) {
        return;
    }
    rds->cmd("DEL sess:%s", sessionId.c_str());
}

} // namespace auth
