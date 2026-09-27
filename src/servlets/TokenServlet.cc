#include "TokenServlet.hpp"

#include "../JwtUtil.hpp"
#include "../OidcConfig.hpp"
#include "../Store.hpp"
#include "../TotpUtil.hpp"
#include "../Util.hpp"
#include "auth/data/oauth_users_info.h"

#include <chen/log/log.h>
#include <chen/util/encryptor_util.h>
#include <chen/util/json_util.h>
#include <chen/util/random_util.h>
#include <chen/util/string_util.h>
#include <chen/util/time_util.h>

namespace auth {

static chen::Logger::ptr logger = LOG_NAME("auth");

static chen::ConfigVar<AuthConf>::ptr g_auth_conf =
    chen::Config::Lookup("auth", AuthConf(), "auth configuration");

TokenServlet::TokenServlet() : AuthServlet("TokenServlet") {}

/// 从请求中提取 client_id 和 client_secret
/// 支持 Basic Auth 头和 POST body 两种方式
static bool extractClientCredentials(chen::http::HttpRequest::ptr request
        , std::string& clientId, std::string& clientSecret) {
    // 先从 POST body 取
    clientId = request->getParam("client_id");
    clientSecret = request->getParam("client_secret");
    if (!clientId.empty() && !clientSecret.empty()) {
        return true;
    }

    // 再从 Authorization: Basic 头取
    std::string auth = request->getHeader("Authorization");
    if (auth.size() > 6 && strncasecmp(auth.c_str(), "Basic ", 6) == 0) {
        std::string decoded = chen::StringUtil::Base64Decode(auth.substr(6));
        auto colon = decoded.find(':');
        if (colon != std::string::npos) {
            clientId = decoded.substr(0, colon);
            clientSecret = decoded.substr(colon + 1);
            return true;
        }
    }

    return !clientId.empty();
}

/// 核验 client_secret
static bool verifyClientSecret(const std::string& clientId, const std::string& clientSecret) {
    Json::Value client = ClientStore::findByClientId(clientId);
    if (client.isNull()) {
        return false;
    }
    std::string hash = client["client_secret_hash"].asString();
    return chen::EncryptorUtil::BCryptVerify(clientSecret, hash);
}

/// 构建 OAuth 错误响应
static void errorResponse(Result::ptr result, chen::http::HttpResponse::ptr response
        , const std::string& error, const std::string& desc = "") {
    result->setResult(400, error);
    if (!desc.empty()) {
        result->set("error_description", desc);
    }
    response->setBody(result->toJsonString());
    response->setHeader("Cache-Control", "no-store");
    response->setHeader("Pragma", "no-cache");
    response->setStatus(chen::http::HttpStatus::BAD_REQUEST);
}

int32_t TokenServlet::handle(chen::http::HttpRequest::ptr request, chen::http::HttpResponse::ptr response
        , chen::http::HttpSession::ptr session, Result::ptr result) {
    std::string grantType = request->getParam("grant_type");

    if (grantType == "authorization_code") {
        return handleAuthCodeGrant(request, response, result);
    }
    if (grantType == "refresh_token") {
        return handleRefreshTokenGrant(request, response, result);
    }
    if (grantType == "totp") {
        return handleTotpGrant(request, response, result);
    }
    if (grantType == "totp_recovery") {
        return handleTotpRecoveryGrant(request, response, result);
    }

    result->setResult(400, "unsupported_grant_type");
    response->setBody(result->toJsonString());
    response->setHeader("Cache-Control", "no-store");
    response->setHeader("Pragma", "no-cache");
    response->setStatus(chen::http::HttpStatus::BAD_REQUEST);
    return 0;
}

int32_t TokenServlet::handleAuthCodeGrant(chen::http::HttpRequest::ptr request, chen::http::HttpResponse::ptr response, Result::ptr result) {
    std::string code = request->getParam("code");
    std::string redirectUri = request->getParam("redirect_uri");

    if (code.empty()) {
        errorResponse(result, response, "invalid_request", "code required");
        return 0;
    }

    // 提取并校验客户端凭证
    std::string clientId, clientSecret;
    if (!extractClientCredentials(request, clientId, clientSecret)) {
        errorResponse(result, response, "invalid_client", "client authentication failed");
        return 0;
    }
    if (!verifyClientSecret(clientId, clientSecret)) {
        errorResponse(result, response, "invalid_client", "client secret mismatch");
        return 0;
    }

    // 消费授权码（原子 GET+DEL）
    Json::Value codeData = AuthCodeStore::consume(code);
    if (codeData.isNull()) {
        errorResponse(result, response, "invalid_grant", "code invalid or expired");
        return 0;
    }

    // 校验 code 与当前请求的 client 和 redirect_uri 一致
    if (codeData["client_id"].asString() != clientId) {
        errorResponse(result, response, "invalid_grant", "code client_id mismatch");
        return 0;
    }
    if (!redirectUri.empty() && codeData["redirect_uri"].asString() != redirectUri) {
        errorResponse(result, response, "invalid_grant", "redirect_uri mismatch");
        return 0;
    }

    int64_t userId = codeData["user_id"].asInt64();
    std::string username = codeData["username"].asString();
    std::string scope = codeData["scope"].asString();
    std::string nonce = codeData["nonce"].asString();
    uint64_t nowMs = chen::GetCurrentMs();
    uint64_t nowSec = nowMs / 1000;

    // ===== 生成 ID Token =====
    Json::Value idTokenPayload;
    idTokenPayload["iss"] = g_auth_conf->getValue().issuer;
    idTokenPayload["sub"] = std::to_string(userId);
    idTokenPayload["aud"] = clientId;
    idTokenPayload["exp"] = static_cast<Json::Int64>(nowSec + g_auth_conf->getValue().token.id_token_ttl);
    idTokenPayload["iat"] = static_cast<Json::Int64>(nowSec);
    idTokenPayload["auth_time"] = static_cast<Json::Int64>(nowSec);
    if (!nonce.empty()) {
        idTokenPayload["nonce"] = nonce;
    }

    // 根据 scope 添加 claims
    auto scopes = chen::StringUtil::Split(scope, ' ');
    for (auto& s : scopes) {
        if (s == "profile") {
            idTokenPayload["name"] = username;
            idTokenPayload["preferred_username"] = username;
        } else if (s == "email") {
            // 需要查用户表获取 email，简化为放 username
            idTokenPayload["email"] = username + "@example.com";
            idTokenPayload["email_verified"] = true;
        }
    }

    const std::string private_key_pem = chen::FSUtil::ReadFileToString(g_auth_conf->getValue().key.private_key_path);

    std::string idToken =
        JwtUtil::CreateJWT(chen::JsonUtil::ToString(idTokenPayload), g_auth_conf->getValue().key.kid, private_key_pem);
    if (idToken.empty()) {
        ERROR(logger) << "create id_token failed";
        errorResponse(result, response, "server_error");
        return 0;
    }

    // ===== 生成 Access Token =====
    Json::Value atPayload;
    atPayload["iss"] = g_auth_conf->getValue().issuer;
    atPayload["sub"] = std::to_string(userId);
    atPayload["aud"] = clientId;
    atPayload["client_id"] = clientId;
    atPayload["exp"] = static_cast<Json::Int64>(nowSec + g_auth_conf->getValue().token.access_token_ttl);
    atPayload["iat"] = static_cast<Json::Int64>(nowSec);
    atPayload["scope"] = scope;

    std::string accessToken =
        JwtUtil::CreateJWT(chen::JsonUtil::ToString(atPayload), g_auth_conf->getValue().key.kid, private_key_pem);
    if (accessToken.empty()) {
        ERROR(logger) << "create access_token failed";
        errorResponse(result, response, "server_error");
        return 0;
    }

    // ===== 生成 Refresh Token =====
    std::string refreshToken = chen::StringUtil::ToLower(chen::StringUtil::HexEncode(chen::RandomUtil::RandBytes(32)));

    Json::Value rtData;
    rtData["client_id"] = clientId;
    rtData["user_id"] = userId;
    rtData["username"] = username;
    rtData["scope"] = scope;
    if (!RefreshTokenStore::save(refreshToken, chen::JsonUtil::ToString(rtData), g_auth_conf->getValue().token.refresh_token_ttl)) {
        ERROR(logger) << "save refresh_token failed";
    }

    // ===== 返回 =====
    result->setResult(200, "ok");
    result->set("access_token", accessToken);
    result->set("token_type", std::string("Bearer"));
    result->set("expires_in", g_auth_conf->getValue().token.access_token_ttl);
    result->set("id_token", idToken);
    result->set("refresh_token", refreshToken);

    response->setBody(result->toJsonString());
    response->setHeader("Cache-Control", "no-store");
    response->setHeader("Pragma", "no-cache");
    response->setStatus(chen::http::HttpStatus::OK);

    INFO(logger) << "token issued for client=" << clientId << " user=" << username;
    return 0;
}

int32_t TokenServlet::handleRefreshTokenGrant(chen::http::HttpRequest::ptr request, chen::http::HttpResponse::ptr response, Result::ptr result) {
    std::string refreshToken = request->getParam("refresh_token");

    if (refreshToken.empty()) {
        errorResponse(result, response, "invalid_request", "refresh_token required");
        return 0;
    }

    // 提取并校验客户端凭证
    std::string clientId, clientSecret;
    if (!extractClientCredentials(request, clientId, clientSecret)) {
        errorResponse(result, response, "invalid_client", "client authentication failed");
        return 0;
    }
    if (!verifyClientSecret(clientId, clientSecret)) {
        errorResponse(result, response, "invalid_client", "client secret mismatch");
        return 0;
    }

    // 消费旧的 refresh token
    Json::Value rtData = RefreshTokenStore::consume(refreshToken);
    if (rtData.isNull()) {
        errorResponse(result, response, "invalid_grant", "refresh token invalid or expired");
        return 0;
    }

    // 校验是否属于同一个 client
    if (rtData["client_id"].asString() != clientId) {
        errorResponse(result, response, "invalid_grant", "refresh token client_id mismatch");
        return 0;
    }

    int64_t userId = rtData["user_id"].asInt64();
    std::string username = rtData["username"].asString();
    std::string scope = rtData["scope"].asString();
    uint64_t nowSec = chen::GetCurrentMs() / 1000;

    // ===== 生成新的 Access Token =====
    Json::Value atPayload;
    atPayload["iss"] = g_auth_conf->getValue().issuer;
    atPayload["sub"] = std::to_string(userId);
    atPayload["aud"] = clientId;
    atPayload["client_id"] = clientId;
    atPayload["exp"] = static_cast<Json::Int64>(nowSec + g_auth_conf->getValue().token.access_token_ttl);
    atPayload["iat"] = static_cast<Json::Int64>(nowSec);
    atPayload["scope"] = scope;

    const std::string private_key_pem = chen::FSUtil::ReadFileToString(g_auth_conf->getValue().key.private_key_path);

    std::string accessToken =
        JwtUtil::CreateJWT(chen::JsonUtil::ToString(atPayload), g_auth_conf->getValue().key.kid, private_key_pem);
    if (accessToken.empty()) {
        ERROR(logger) << "create access_token failed on refresh";
        errorResponse(result, response, "server_error");
        return 0;
    }

    // ===== 生成新的 Refresh Token（轮换） =====
    std::string newRT = chen::StringUtil::ToLower(chen::StringUtil::HexEncode(chen::RandomUtil::RandBytes(32)));

    Json::Value newRtData;
    newRtData["client_id"] = clientId;
    newRtData["user_id"] = userId;
    newRtData["username"] = username;
    newRtData["scope"] = scope;
    if (!RefreshTokenStore::save(newRT, chen::JsonUtil::ToString(newRtData), g_auth_conf->getValue().token.refresh_token_ttl)) {
        ERROR(logger) << "save new refresh_token failed";
    }

    // ===== 返回 =====
    result->setResult(200, "ok");
    result->set("access_token", accessToken);
    result->set("token_type", std::string("Bearer"));
    result->set("expires_in", g_auth_conf->getValue().token.access_token_ttl);
    result->set("refresh_token", newRT);

    response->setBody(result->toJsonString());
    response->setHeader("Cache-Control", "no-store");
    response->setHeader("Pragma", "no-cache");
    response->setStatus(chen::http::HttpStatus::OK);

    INFO(logger) << "token refreshed for client=" << clientId;
    return 0;
}

// ============================================================================
// grant_type=totp — 两步登录第二步：temp_token + TOTP 码 → 签发 Token
// ============================================================================
int32_t TokenServlet::handleTotpGrant(chen::http::HttpRequest::ptr request, chen::http::HttpResponse::ptr response, Result::ptr result) {
    std::string tempToken = request->getParam("temp_token");
    std::string totpCode = request->getParam("totp_code");

    if (tempToken.empty() || totpCode.empty()) {
        errorResponse(result, response, "invalid_request", "temp_token and totp_code required");
        return 0;
    }

    // 提取并校验客户端凭证
    std::string clientId, clientSecret;
    if (!extractClientCredentials(request, clientId, clientSecret)) {
        errorResponse(result, response, "invalid_client", "client authentication failed");
        return 0;
    }
    if (!verifyClientSecret(clientId, clientSecret)) {
        errorResponse(result, response, "invalid_client", "client secret mismatch");
        return 0;
    }

    // 从 Redis 取出 temp_token 对应的 userId
    auto rds = GetRedis();
    if (!rds) {
        errorResponse(result, response, "server_error");
        return 0;
    }

    std::string redisKey = "2fa_pending:" + tempToken;
    auto reply = rds->cmd("GET %s", redisKey.c_str());
    if (!reply || reply->type != REDIS_REPLY_STRING) {
        errorResponse(result, response, "invalid_grant", "temp_token invalid or expired");
        return 0;
    }
    int64_t userId = 0;
    try {
        userId = std::stoll(std::string(reply->str, reply->len));
    } catch (...) {
        errorResponse(result, response, "invalid_grant", "temp_token invalid");
        return 0;
    }

    // 删除 temp_token（一次性）
    rds->cmd("DEL %s", redisKey.c_str());

    // 验证 TOTP 码
    std::string totpSecret = UserStore::getTotpSecret(userId);
    if (totpSecret.empty() || !TotpUtil::VerifyCode(totpSecret, totpCode, 1)) {
        WARN(logger) << "totp verify failed for user=" << userId;
        errorResponse(result, response, "invalid_grant", "invalid TOTP code");
        return 0;
    }

    // TOTP 验证通过，签发 Token
    Json::Value user = UserStore::findByUsername(
        [&]() -> std::string {
            auto db = GetDB();
            auto info = auth::data::OauthUsersInfoDao::Query(userId, db);
            return info ? info->getUsername() : "";
        }());
    if (user.isNull()) {
        errorResponse(result, response, "server_error", "user not found");
        return 0;
    }

    std::string username = user["username"].asString();
    std::string scope = "openid profile email";
    uint64_t nowSec = chen::GetCurrentMs() / 1000;

    const std::string private_key_pem = chen::FSUtil::ReadFileToString(g_auth_conf->getValue().key.private_key_path);

    // ID Token
    Json::Value idTokenPayload;
    idTokenPayload["iss"] = g_auth_conf->getValue().issuer;
    idTokenPayload["sub"] = std::to_string(userId);
    idTokenPayload["aud"] = clientId;
    idTokenPayload["exp"] = static_cast<Json::Int64>(nowSec + g_auth_conf->getValue().token.id_token_ttl);
    idTokenPayload["iat"] = static_cast<Json::Int64>(nowSec);
    idTokenPayload["auth_time"] = static_cast<Json::Int64>(nowSec);

    std::string idToken = JwtUtil::CreateJWT(chen::JsonUtil::ToString(idTokenPayload),
        g_auth_conf->getValue().key.kid, private_key_pem);
    if (idToken.empty()) {
        errorResponse(result, response, "server_error", "failed to create id_token");
        return 0;
    }

    // Access Token
    Json::Value atPayload;
    atPayload["iss"] = g_auth_conf->getValue().issuer;
    atPayload["sub"] = std::to_string(userId);
    atPayload["aud"] = clientId;
    atPayload["client_id"] = clientId;
    atPayload["exp"] = static_cast<Json::Int64>(nowSec + g_auth_conf->getValue().token.access_token_ttl);
    atPayload["iat"] = static_cast<Json::Int64>(nowSec);
    atPayload["scope"] = scope;

    std::string accessToken = JwtUtil::CreateJWT(chen::JsonUtil::ToString(atPayload),
        g_auth_conf->getValue().key.kid, private_key_pem);
    if (accessToken.empty()) {
        errorResponse(result, response, "server_error", "failed to create access_token");
        return 0;
    }

    // Refresh Token
    std::string refreshToken = chen::StringUtil::ToLower(chen::StringUtil::HexEncode(chen::RandomUtil::RandBytes(32)));
    Json::Value rtData;
    rtData["client_id"] = clientId;
    rtData["user_id"] = userId;
    rtData["username"] = username;
    rtData["scope"] = scope;
    RefreshTokenStore::save(refreshToken, chen::JsonUtil::ToString(rtData),
        g_auth_conf->getValue().token.refresh_token_ttl);

    // 返回
    result->setResult(200, "ok");
    result->set("access_token", accessToken);
    result->set("token_type", std::string("Bearer"));
    result->set("expires_in", g_auth_conf->getValue().token.access_token_ttl);
    result->set("id_token", idToken);
    result->set("refresh_token", refreshToken);

    response->setBody(result->toJsonString());
    response->setHeader("Cache-Control", "no-store");
    response->setHeader("Pragma", "no-cache");
    response->setStatus(chen::http::HttpStatus::OK);

    INFO(logger) << "totp token issued for client=" << clientId << " user=" << username;
    return 0;
}

// ============================================================================
// grant_type=totp_recovery — 恢复码登录
// ============================================================================
int32_t TokenServlet::handleTotpRecoveryGrant(chen::http::HttpRequest::ptr request, chen::http::HttpResponse::ptr response, Result::ptr result) {
    std::string tempToken = request->getParam("temp_token");
    std::string recoveryCode = request->getParam("recovery_code");

    if (tempToken.empty() || recoveryCode.empty()) {
        errorResponse(result, response, "invalid_request", "temp_token and recovery_code required");
        return 0;
    }

    // 提取并校验客户端凭证
    std::string clientId, clientSecret;
    if (!extractClientCredentials(request, clientId, clientSecret)) {
        errorResponse(result, response, "invalid_client", "client authentication failed");
        return 0;
    }
    if (!verifyClientSecret(clientId, clientSecret)) {
        errorResponse(result, response, "invalid_client", "client secret mismatch");
        return 0;
    }

    // 从 Redis 取出 temp_token
    auto rds = GetRedis();
    if (!rds) {
        errorResponse(result, response, "server_error");
        return 0;
    }

    std::string redisKey = "2fa_pending:" + tempToken;
    auto reply = rds->cmd("GET %s", redisKey.c_str());
    if (!reply || reply->type != REDIS_REPLY_STRING) {
        errorResponse(result, response, "invalid_grant", "temp_token invalid or expired");
        return 0;
    }
    int64_t userId = 0;
    try {
        userId = std::stoll(std::string(reply->str, reply->len));
    } catch (...) {
        errorResponse(result, response, "invalid_grant", "temp_token invalid");
        return 0;
    }

    // 删除 temp_token（一次性）
    rds->cmd("DEL %s", redisKey.c_str());

    // 验证恢复码
    if (!RecoveryCodeStore::consume(userId, recoveryCode)) {
        WARN(logger) << "recovery code verify failed for user=" << userId;
        errorResponse(result, response, "invalid_grant", "invalid or used recovery code");
        return 0;
    }

    // 恢复码验证通过，签发 Token（同 handleTotpGrant 的签发逻辑）
    auto db = GetDB();
    auto userInfo = auth::data::OauthUsersInfoDao::Query(userId, db);
    if (!userInfo) {
        errorResponse(result, response, "server_error", "user not found");
        return 0;
    }

    std::string username = userInfo->getUsername();
    std::string scope = "openid profile email";
    uint64_t nowSec = chen::GetCurrentMs() / 1000;

    const std::string private_key_pem = chen::FSUtil::ReadFileToString(g_auth_conf->getValue().key.private_key_path);

    Json::Value idTokenPayload;
    idTokenPayload["iss"] = g_auth_conf->getValue().issuer;
    idTokenPayload["sub"] = std::to_string(userId);
    idTokenPayload["aud"] = clientId;
    idTokenPayload["exp"] = static_cast<Json::Int64>(nowSec + g_auth_conf->getValue().token.id_token_ttl);
    idTokenPayload["iat"] = static_cast<Json::Int64>(nowSec);
    idTokenPayload["auth_time"] = static_cast<Json::Int64>(nowSec);

    std::string idToken = JwtUtil::CreateJWT(chen::JsonUtil::ToString(idTokenPayload),
        g_auth_conf->getValue().key.kid, private_key_pem);
    if (idToken.empty()) {
        errorResponse(result, response, "server_error", "failed to create id_token");
        return 0;
    }

    Json::Value atPayload;
    atPayload["iss"] = g_auth_conf->getValue().issuer;
    atPayload["sub"] = std::to_string(userId);
    atPayload["aud"] = clientId;
    atPayload["client_id"] = clientId;
    atPayload["exp"] = static_cast<Json::Int64>(nowSec + g_auth_conf->getValue().token.access_token_ttl);
    atPayload["iat"] = static_cast<Json::Int64>(nowSec);
    atPayload["scope"] = scope;

    std::string accessToken = JwtUtil::CreateJWT(chen::JsonUtil::ToString(atPayload),
        g_auth_conf->getValue().key.kid, private_key_pem);
    if (accessToken.empty()) {
        errorResponse(result, response, "server_error", "failed to create access_token");
        return 0;
    }

    std::string refreshToken = chen::StringUtil::ToLower(chen::StringUtil::HexEncode(chen::RandomUtil::RandBytes(32)));
    Json::Value rtData;
    rtData["client_id"] = clientId;
    rtData["user_id"] = userId;
    rtData["username"] = username;
    rtData["scope"] = scope;
    RefreshTokenStore::save(refreshToken, chen::JsonUtil::ToString(rtData),
        g_auth_conf->getValue().token.refresh_token_ttl);

    result->setResult(200, "ok");
    result->set("access_token", accessToken);
    result->set("token_type", std::string("Bearer"));
    result->set("expires_in", g_auth_conf->getValue().token.access_token_ttl);
    result->set("id_token", idToken);
    result->set("refresh_token", refreshToken);

    response->setBody(result->toJsonString());
    response->setHeader("Cache-Control", "no-store");
    response->setHeader("Pragma", "no-cache");
    response->setStatus(chen::http::HttpStatus::OK);

    INFO(logger) << "recovery token issued for client=" << clientId << " user=" << username;
    return 0;
}

} // namespace auth
