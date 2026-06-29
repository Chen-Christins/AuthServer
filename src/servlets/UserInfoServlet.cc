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
        result->setResult(401, "invalid_token");
        result->set("error_description", "missing Bearer token");
        response->setBody(result->toJsonString());
        response->setHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"");
        response->setStatus(chen::http::HttpStatus::UNAUTHORIZED);
        return 0;
    }

    std::string token = auth.substr(7);

    // ========== 2. 验证 JWT 签名 ==========
    Json::Value payload;
    if (!JwtUtil::verifyJWT(token, OidcConfig::publicKeyPem, payload)) {
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

    // ========== 4. 构建 UserInfo 响应 ==========
    std::string scope = payload.get("scope", "").asString();
    auto scopes = chen::StringUtil::Split(scope, ' ');

    result->setResult(200, "ok");
    result->set("sub", payload["sub"].asString());

    for (auto& s : scopes) {
        if (s == "profile") {
            result->set("name", payload.get("name", "").asString());
            result->set("preferred_username",
                         payload.get("preferred_username", "").asString());
        } else if (s == "email") {
            result->set("email", payload.get("email", "").asString());
            result->set("email_verified",
                         payload.get("email_verified", false).asInt());
        }
    }

    response->setBody(result->toJsonString());
    response->setStatus(chen::http::HttpStatus::OK);

    INFO(logger) << "userinfo success sub=" << payload["sub"].asString();
    return 0;
}

} // namespace auth
