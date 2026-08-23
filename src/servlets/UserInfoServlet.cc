#include "UserInfoServlet.hpp"

#include "../JwtUtil.hpp"
#include "../OidcConfig.hpp"
#include "../util.h"
#include "auth/data/oauth_users_info.h"

#include <chen/log/log.h>
#include <chen/util/string_util.h>
#include <chen/util/time_util.h>

namespace auth {

static chen::Logger::ptr logger = LOG_NAME("auth");

static chen::ConfigVar<AuthConf>::ptr g_auth_conf =
    chen::Config::Lookup("auth", AuthConf(), "auth configuration");


UserInfoServlet::UserInfoServlet() : AuthServlet("UserInfoServlet") {}

int32_t UserInfoServlet::handle(chen::http::HttpRequest::ptr request, chen::http::HttpResponse::ptr response
        , chen::http::HttpSession::ptr session, Result::ptr result) {
    // ========== 1. 提取 Bearer Token ==========
    std::string auth = request->getHeader("Authorization");
    if (auth.size() <= 7 || strncasecmp(auth.c_str(), "Bearer ", 7) != 0) {
        result->setResult(401, "invalid_token");
        result->set("error_description", "missing Bearer token");
        response->setBody(result->toJsonString());
        response->setHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"");
        response->setStatus(chen::http::HttpStatus::UNAUTHORIZED);
        return 0;
    }

    std::string token = auth.substr(7);


    const std::string private_key_pem = chen::FSUtil::ReadFileToString(g_auth_conf->getValue().key.private_key_path);
    // ========== 2. 验证 JWT 签名 ==========
    Json::Value payload;
    if (!JwtUtil::verifyJWT(token, private_key_pem, payload)) {
        WARN(logger) << "userinfo: invalid token signature";
        result->setResult(401, "invalid_token");
        response->setBody(result->toJsonString());
        response->setHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"");
        response->setStatus(chen::http::HttpStatus::UNAUTHORIZED);
        return 0;
    }

    // ========== 3. 检查过期 ==========
    uint64_t nowSec = chen::GetCurrentMs() / 1000;
    if (payload["exp"].asInt64() < static_cast<int64_t>(nowSec)) {
        WARN(logger) << "userinfo: token expired";
        result->setResult(401, "invalid_token");
        result->set("error_description", "token expired");
        response->setBody(result->toJsonString());
        response->setHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"");
        response->setStatus(chen::http::HttpStatus::UNAUTHORIZED);
        return 0;
    }

    // ========== 4. 从数据库查用户信息 ==========
    int64_t userId = std::stoll(payload["sub"].asString());
    std::string scope = payload.get("scope", "").asString();
    auto scopes = chen::StringUtil::Split(scope, ' ');

    // Token 中的 sub 是用户 ID，查数据库
    auto userInfo = auth::data::OauthUsersInfoDao::Query(userId, GetDB());
    if (!userInfo) {
        ERROR(logger) << "userinfo: user not found, sub=" << payload["sub"].asString();
        result->setResult(404, "user_not_found");
        response->setBody(result->toJsonString());
        response->setStatus(chen::http::HttpStatus::NOT_FOUND);
        return 0;
    }

    // ========== 5. 根据 scope 返回 claims ==========
    result->setResult(200, "ok");
    result->set("sub", payload["sub"].asString());

    for (auto& s : scopes) {
        if (s == "profile") {
            result->set("name", userInfo->getDisplayName());
            result->set("preferred_username", userInfo->getUsername());
        } else if (s == "email") {
            result->set("email", userInfo->getEmail());
            result->set("email_verified", userInfo->getEmailVerified());
        }
    }

    response->setBody(result->toJsonString());
    response->setStatus(chen::http::HttpStatus::OK);

    INFO(logger) << "userinfo success sub=" << payload["sub"].asString();
    return 0;
}

} // namespace auth
