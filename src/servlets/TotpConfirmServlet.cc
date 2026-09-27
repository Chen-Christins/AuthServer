#include "TotpConfirmServlet.hpp"

#include "../JwtUtil.hpp"
#include "../OidcConfig.hpp"
#include "../Store.hpp"
#include "../TotpUtil.hpp"
#include "../Util.hpp"

#include <chen/log/log.h>
#include <chen/util/json_util.h>

namespace auth {

static chen::Logger::ptr logger = LOG_NAME("auth");

TotpConfirmServlet::TotpConfirmServlet() : AuthServlet("TotpConfirmServlet") {}

int32_t TotpConfirmServlet::handle(chen::http::HttpRequest::ptr request, chen::http::HttpResponse::ptr response
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

    // 从 Redis 取出待确认的密钥
    auto rds = GetRedis();
    if (!rds) {
        result->setResult(500, "server_error");
        response->setBody(result->toJsonString());
        response->setStatus(chen::http::HttpStatus::INTERNAL_SERVER_ERROR);
        return 0;
    }

    std::string redisKey = "totp_pending:" + std::to_string(userId);
    auto reply = rds->cmd("GET %s", redisKey.c_str());
    if (!reply || reply->type != REDIS_REPLY_STRING) {
        result->setResult(400, "totp_setup_required");
        result->set("error_description", "call /totp/setup first");
        response->setBody(result->toJsonString());
        response->setStatus(chen::http::HttpStatus::BAD_REQUEST);
        return 0;
    }
    std::string secret(reply->str, reply->len);

    // 验证 TOTP 码
    if (!TotpUtil::VerifyCode(secret, code, 1)) {
        result->setResult(400, "invalid_totp_code");
        result->set("error_description", "invalid TOTP code");
        response->setBody(result->toJsonString());
        response->setStatus(chen::http::HttpStatus::BAD_REQUEST);
        return 0;
    }

    // 验证通过，写入 DB
    if (!UserStore::setTotp(userId, secret, true)) {
        result->setResult(500, "server_error");
        response->setBody(result->toJsonString());
        response->setStatus(chen::http::HttpStatus::INTERNAL_SERVER_ERROR);
        return 0;
    }

    // 删除 Redis 中的临时密钥
    rds->cmd("DEL %s", redisKey.c_str());

    // 生成恢复码
    std::vector<std::string> hashedCodes;
    std::vector<std::string> recoveryCodes = TotpUtil::GenerateRecoveryCodes(10, hashedCodes);
    RecoveryCodeStore::save(userId, hashedCodes);

    // 返回恢复码（仅此一次）
    Json::Value codesArr;
    for (auto& c : recoveryCodes) {
        codesArr.append(c);
    }
    result->setResult(200, "ok");
    result->set("recovery_codes", codesArr);

    response->setBody(result->toJsonString());
    response->setStatus(chen::http::HttpStatus::OK);
    INFO(logger) << "totp confirmed for user=" << userId;
    return 0;
}

} // namespace auth
