#include "TokenServlet.hpp"

#include "../JwtUtil.hpp"
#include "../OidcConfig.hpp"
#include "../Store.hpp"

#include <chen/log/log.h>
#include <chen/util/encryptor_util.h>
#include <chen/util/json_util.h>
#include <chen/util/random_util.h>
#include <chen/util/string_util.h>
#include <chen/util/time_util.h>

namespace auth {

static chen::Logger::ptr logger = LOG_NAME("auth.token");

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
static void errorResponse(chen::http::HttpResponse::ptr response, const std::string& error
        , const std::string& desc = "") {
    Json::Value body;
    body["error"] = error;
    if (!desc.empty()) {
        body["error_description"] = desc;
    }
    response->setBody(chen::JsonUtil::ToString(body));
    response->setHeader("Content-Type", "application/json");
    response->setHeader("Cache-Control", "no-store");
    response->setHeader("Pragma", "no-cache");
    response->setStatus(chen::http::HttpStatus::BAD_REQUEST);
}

int32_t TokenServlet::handle(chen::http::HttpRequest::ptr request, chen::http::HttpResponse::ptr response
        , chen::http::HttpSession::ptr session, Result::ptr result) {
    std::string grantType = request->getParam("grant_type");

    if (grantType == "authorization_code") {
        return handleAuthCodeGrant(request, response);
    }
    if (grantType == "refresh_token") {
        return handleRefreshTokenGrant(request, response);
    }

    errorResponse(response, "unsupported_grant_type");
    return 0;
}

int32_t TokenServlet::handleAuthCodeGrant(chen::http::HttpRequest::ptr request, chen::http::HttpResponse::ptr response) {
    std::string code = request->getParam("code");
    std::string redirectUri = request->getParam("redirect_uri");

    if (code.empty()) {
        errorResponse(response, "invalid_request", "code required");
        return 0;
    }

    // 提取并校验客户端凭证
    std::string clientId, clientSecret;
    if (!extractClientCredentials(request, clientId, clientSecret)) {
        errorResponse(response, "invalid_client", "client authentication failed");
        return 0;
    }
    if (!verifyClientSecret(clientId, clientSecret)) {
        errorResponse(response, "invalid_client", "client secret mismatch");
        return 0;
    }

    // 消费授权码（原子 GET+DEL）
    Json::Value codeData = AuthCodeStore::consume(code);
    if (codeData.isNull()) {
        errorResponse(response, "invalid_grant", "code invalid or expired");
        return 0;
    }

    // 校验 code 与当前请求的 client 和 redirect_uri 一致
    if (codeData["client_id"].asString() != clientId) {
        errorResponse(response, "invalid_grant", "code client_id mismatch");
        return 0;
    }
    if (!redirectUri.empty() && codeData["redirect_uri"].asString() != redirectUri) {
        errorResponse(response, "invalid_grant", "redirect_uri mismatch");
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
    idTokenPayload["iss"] = OidcConfig::issuer;
    idTokenPayload["sub"] = std::to_string(userId);
    idTokenPayload["aud"] = clientId;
    idTokenPayload["exp"] = static_cast<Json::Int64>(nowSec + OidcConfig::idTokenTtl);
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

    std::string idToken =
        JwtUtil::createJWT(chen::JsonUtil::ToString(idTokenPayload), OidcConfig::kid, OidcConfig::privateKeyPem);
    if (idToken.empty()) {
        ERROR(logger) << "create id_token failed";
        errorResponse(response, "server_error");
        return 0;
    }

    // ===== 生成 Access Token =====
    Json::Value atPayload;
    atPayload["iss"] = OidcConfig::issuer;
    atPayload["sub"] = std::to_string(userId);
    atPayload["aud"] = clientId;
    atPayload["client_id"] = clientId;
    atPayload["exp"] = static_cast<Json::Int64>(nowSec + OidcConfig::accessTokenTtl);
    atPayload["iat"] = static_cast<Json::Int64>(nowSec);
    atPayload["scope"] = scope;

    std::string accessToken =
        JwtUtil::createJWT(chen::JsonUtil::ToString(atPayload), OidcConfig::kid, OidcConfig::privateKeyPem);
    if (accessToken.empty()) {
        ERROR(logger) << "create access_token failed";
        errorResponse(response, "server_error");
        return 0;
    }

    // ===== 生成 Refresh Token =====
    std::string refreshToken = chen::StringUtil::ToLower(chen::StringUtil::HexEncode(chen::RandomUtil::RandBytes(32)));

    Json::Value rtData;
    rtData["client_id"] = clientId;
    rtData["user_id"] = userId;
    rtData["username"] = username;
    rtData["scope"] = scope;
    if (!RefreshTokenStore::save(refreshToken, chen::JsonUtil::ToString(rtData), OidcConfig::refreshTokenTtl)) {
        ERROR(logger) << "save refresh_token failed";
    }

    // ===== 返回 =====
    Json::Value tokenRes;
    tokenRes["access_token"] = accessToken;
    tokenRes["token_type"] = "Bearer";
    tokenRes["expires_in"] = OidcConfig::accessTokenTtl;
    tokenRes["id_token"] = idToken;
    tokenRes["refresh_token"] = refreshToken;

    response->setBody(chen::JsonUtil::ToString(tokenRes));
    response->setHeader("Content-Type", "application/json");
    response->setHeader("Cache-Control", "no-store");
    response->setHeader("Pragma", "no-cache");
    response->setStatus(chen::http::HttpStatus::OK);

    INFO(logger) << "token issued for client=" << clientId << " user=" << username;
    return 0;
}

int32_t TokenServlet::handleRefreshTokenGrant(chen::http::HttpRequest::ptr request, chen::http::HttpResponse::ptr response) {
    std::string refreshToken = request->getParam("refresh_token");

    if (refreshToken.empty()) {
        errorResponse(response, "invalid_request", "refresh_token required");
        return 0;
    }

    // 提取并校验客户端凭证
    std::string clientId, clientSecret;
    if (!extractClientCredentials(request, clientId, clientSecret)) {
        errorResponse(response, "invalid_client", "client authentication failed");
        return 0;
    }
    if (!verifyClientSecret(clientId, clientSecret)) {
        errorResponse(response, "invalid_client", "client secret mismatch");
        return 0;
    }

    // 消费旧的 refresh token
    Json::Value rtData = RefreshTokenStore::consume(refreshToken);
    if (rtData.isNull()) {
        errorResponse(response, "invalid_grant", "refresh token invalid or expired");
        return 0;
    }

    // 校验是否属于同一个 client
    if (rtData["client_id"].asString() != clientId) {
        errorResponse(response, "invalid_grant", "refresh token client_id mismatch");
        return 0;
    }

    int64_t userId = rtData["user_id"].asInt64();
    std::string username = rtData["username"].asString();
    std::string scope = rtData["scope"].asString();
    uint64_t nowSec = chen::GetCurrentMs() / 1000;

    // ===== 生成新的 Access Token =====
    Json::Value atPayload;
    atPayload["iss"] = OidcConfig::issuer;
    atPayload["sub"] = std::to_string(userId);
    atPayload["aud"] = clientId;
    atPayload["client_id"] = clientId;
    atPayload["exp"] = static_cast<Json::Int64>(nowSec + OidcConfig::accessTokenTtl);
    atPayload["iat"] = static_cast<Json::Int64>(nowSec);
    atPayload["scope"] = scope;

    std::string accessToken =
        JwtUtil::createJWT(chen::JsonUtil::ToString(atPayload), OidcConfig::kid, OidcConfig::privateKeyPem);
    if (accessToken.empty()) {
        ERROR(logger) << "create access_token failed on refresh";
        errorResponse(response, "server_error");
        return 0;
    }

    // ===== 生成新的 Refresh Token（轮换） =====
    std::string newRT = chen::StringUtil::ToLower(chen::StringUtil::HexEncode(chen::RandomUtil::RandBytes(32)));

    Json::Value newRtData;
    newRtData["client_id"] = clientId;
    newRtData["user_id"] = userId;
    newRtData["username"] = username;
    newRtData["scope"] = scope;
    if (!RefreshTokenStore::save(newRT, chen::JsonUtil::ToString(newRtData), OidcConfig::refreshTokenTtl)) {
        ERROR(logger) << "save new refresh_token failed";
    }

    // ===== 返回 =====
    Json::Value tokenRes;
    tokenRes["access_token"] = accessToken;
    tokenRes["token_type"] = "Bearer";
    tokenRes["expires_in"] = OidcConfig::accessTokenTtl;
    tokenRes["refresh_token"] = newRT;

    response->setBody(chen::JsonUtil::ToString(tokenRes));
    response->setHeader("Content-Type", "application/json");
    response->setHeader("Cache-Control", "no-store");
    response->setHeader("Pragma", "no-cache");
    response->setStatus(chen::http::HttpStatus::OK);

    INFO(logger) << "token refreshed for client=" << clientId;
    return 0;
}

} // namespace auth
