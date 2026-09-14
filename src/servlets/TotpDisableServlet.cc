#include "TotpDisableServlet.hpp"

#include "../OidcConfig.hpp"
#include "../Store.hpp"
#include "../TotpUtil.hpp"
#include "../JwtUtil.hpp"

#include <chen/log/log.h>
#include <chen/util/json_util.h>

namespace auth {

static chen::Logger::ptr logger = LOG_NAME("auth");

TotpDisableServlet::TotpDisableServlet() : AuthServlet("TotpDisableServlet") {}

int32_t TotpDisableServlet::handle(chen::http::HttpRequest::ptr request, chen::http::HttpResponse::ptr response
        , chen::http::HttpSession::ptr session, Result::ptr result) {
    if (request->getMethod() != chen::http::HttpMethod::POST) {
        response->setStatus(chen::http::HttpStatus::METHOD_NOT_ALLOWED);
        return 0;
    }

    // 验证 Bearer Token
    std::string auth = request->getHeader("Authorization");
    if (auth.size() <= 7 || strncasecmp(auth.c_str(), "Bearer ", 7) != 0) {
        result->setResult(401, "invalid_token");
        result->set("error_description", "missing Bearer token");
        response->setBody(result->toJsonString());
        response->setStatus(chen::http::HttpStatus::UNAUTHORIZED);
        return 0;
    }

    std::string token = auth.substr(7);
    const std::string public_key_pem = chen::FSUtil::ReadFileToString(
        chen::Config::Lookup("auth", AuthConf(), "auth configuration")->getValue().key.public_key_path);

    Json::Value payload;
    if (!JwtUtil::VerifyJWT(token, public_key_pem, payload)) {
        result->setResult(401, "invalid_token");
        response->setBody(result->toJsonString());
        response->setStatus(chen::http::HttpStatus::UNAUTHORIZED);
        return 0;
    }

    int64_t userId = std::stoll(payload["sub"].asString());

    // 解析请求体
    Json::Value body;
    if (!chen::JsonUtil::FromString(body, request->getBody())) {
        result->setResult(400, "invalid_request");
        result->set("error_description", "invalid JSON body");
        response->setBody(result->toJsonString());
        response->setStatus(chen::http::HttpStatus::BAD_REQUEST);
        return 0;
    }

    std::string code = body.get("code", "").asString();
    if (code.empty()) {
        result->setResult(400, "invalid_request");
        result->set("error_description", "code required");
        response->setBody(result->toJsonString());
        response->setStatus(chen::http::HttpStatus::BAD_REQUEST);
        return 0;
    }

    // 检查 2FA 是否已启用
    if (!UserStore::isTotpEnabled(userId)) {
        result->setResult(409, "totp_not_enabled");
        result->set("error_description", "two-factor authentication not enabled");
        response->setBody(result->toJsonString());
        response->setStatus(chen::http::HttpStatus::CONFLICT);
        return 0;
    }

    // 验证 TOTP 码（必须验证通过才能禁用）
    std::string secret = UserStore::getTotpSecret(userId);
    if (!TotpUtil::VerifyCode(secret, code, 1)) {
        result->setResult(400, "invalid_totp_code");
        result->set("error_description", "invalid TOTP code");
        response->setBody(result->toJsonString());
        response->setStatus(chen::http::HttpStatus::BAD_REQUEST);
        return 0;
    }

    // 禁用 2FA
    if (!UserStore::setTotp(userId, "", false)) {
        result->setResult(500, "server_error");
        response->setBody(result->toJsonString());
        response->setStatus(chen::http::HttpStatus::INTERNAL_SERVER_ERROR);
        return 0;
    }

    // 删除恢复码
    RecoveryCodeStore::removeAll(userId);

    result->setResult(200, "ok");
    response->setBody(result->toJsonString());
    response->setStatus(chen::http::HttpStatus::OK);
    INFO(logger) << "totp disabled for user=" << userId;
    return 0;
}

} // namespace auth
