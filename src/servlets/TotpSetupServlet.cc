#include "TotpSetupServlet.hpp"

#include "../JwtUtil.hpp"
#include "../OidcConfig.hpp"
#include "../Store.hpp"
#include "../TotpUtil.hpp"
#include "../Util.hpp"

#include <chen/log/log.h>

namespace auth {

static chen::Logger::ptr logger = LOG_NAME("auth");

TotpSetupServlet::TotpSetupServlet() : AuthServlet("TotpSetupServlet") {}

int32_t TotpSetupServlet::handle(chen::http::HttpRequest::ptr request, chen::http::HttpResponse::ptr response
        , chen::http::HttpSession::ptr session, Result::ptr result) {
    if (request->getMethod() != chen::http::HttpMethod::POST) {
        response->setStatus(chen::http::HttpStatus::METHOD_NOT_ALLOWED);
        return 0;
    }

    // 提取 Bearer Token 并验证
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
    std::string username = payload.get("preferred_username", payload.get("sub", "")).asString();

    // 检查是否已启用 2FA
    if (UserStore::isTotpEnabled(userId)) {
        result->setResult(409, "totp_already_enabled");
        result->set("error_description", "two-factor authentication already enabled");
        response->setBody(result->toJsonString());
        response->setStatus(chen::http::HttpStatus::CONFLICT);
        return 0;
    }

    // 生成密钥
    std::string secret = TotpUtil::GenerateSecret();
    std::string otpUri = TotpUtil::GetOtpUri(secret, username);

    // 将密钥临时存入 Redis（等 confirm 时再正式写入 DB）
    auto rds = GetRedis();
    if (!rds) {
        result->setResult(500, "server_error");
        response->setBody(result->toJsonString());
        response->setStatus(chen::http::HttpStatus::INTERNAL_SERVER_ERROR);
        return 0;
    }
    rds->cmd("SETEX totp_pending:%lld 300 %s", (long long)userId, secret.c_str());

    result->setResult(200, "ok");
    result->set("secret", secret);
    result->set("otp_uri", otpUri);

    response->setBody(result->toJsonString());
    response->setStatus(chen::http::HttpStatus::OK);
    INFO(logger) << "totp setup for user=" << userId;
    return 0;
}

} // namespace auth
