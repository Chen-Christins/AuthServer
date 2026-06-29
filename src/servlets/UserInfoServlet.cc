#include "UserInfoServlet.hpp"

#include "../JwtUtil.hpp"
#include "../OidcConfig.hpp"

#include <chen/log/log.h>
#include <chen/util/json_util.h>
#include <chen/util/string_util.h>
#include <chen/util/time_util.h>

namespace auth {

static chen::Logger::ptr logger = LOG_NAME("auth.userinfo");

UserInfoServlet::UserInfoServlet() : AuthServlet("UserInfoServlet") {}

int32_t UserInfoServlet::handle(chen::http::HttpRequest::ptr request, chen::http::HttpResponse::ptr response
        , chen::http::HttpSession::ptr session, Result::ptr result) {
    // ========== 1. 提取 Bearer Token ==========
    std::string auth = request->getHeader("Authorization");
    if (auth.size() <= 7 || strncasecmp(auth.c_str(), "Bearer ", 7) != 0) {
        response->setBody("{\"error\":\"invalid_token\","
                          "\"error_description\":\"missing Bearer token\"}");
        response->setHeader("Content-Type", "application/json");
        response->setHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"");
        response->setStatus(chen::http::HttpStatus::UNAUTHORIZED);
        return 0;
    }

    std::string token = auth.substr(7);

    // ========== 2. 验证 JWT 签名 ==========
    Json::Value payload;
    if (!JwtUtil::verifyJWT(token, OidcConfig::publicKeyPem, payload)) {
        WARN(logger) << "userinfo: invalid token signature";
        response->setBody("{\"error\":\"invalid_token\"}");
        response->setHeader("Content-Type", "application/json");
        response->setHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"");
        response->setStatus(chen::http::HttpStatus::UNAUTHORIZED);
        return 0;
    }

    // ========== 3. 检查过期 ==========
    uint64_t nowSec = chen::GetCurrentMs() / 1000;
    if (payload["exp"].asInt64() < static_cast<int64_t>(nowSec)) {
        WARN(logger) << "userinfo: token expired";
        response->setBody("{\"error\":\"invalid_token\","
                          "\"error_description\":\"token expired\"}");
        response->setHeader("Content-Type", "application/json");
        response->setHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"");
        response->setStatus(chen::http::HttpStatus::UNAUTHORIZED);
        return 0;
    }

    // ========== 4. 构建 UserInfo 响应 ==========
    // sub = 用户 ID（字符串形式）
    // 从 token 的 payload 中提取 scope 决定返回哪些 claims
    std::string scope = payload.get("scope", "").asString();
    auto scopes = chen::StringUtil::Split(scope, ' ');

    Json::Value userInfo;
    userInfo["sub"] = payload["sub"].asString();

    for (auto& s : scopes) {
        if (s == "profile") {
            userInfo["name"] = payload.get("name", "");
            userInfo["preferred_username"] = payload.get("preferred_username", "");
        } else if (s == "email") {
            userInfo["email"] = payload.get("email", "");
            userInfo["email_verified"] = payload.get("email_verified", false);
        }
    }

    response->setBody(chen::JsonUtil::ToString(userInfo));
    response->setHeader("Content-Type", "application/json");
    response->setStatus(chen::http::HttpStatus::OK);

    INFO(logger) << "userinfo success sub=" << payload["sub"].asString();
    return 0;
}

} // namespace auth
