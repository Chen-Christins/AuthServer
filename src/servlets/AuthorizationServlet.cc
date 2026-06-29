#include "AuthorizationServlet.hpp"

#include "../OidcConfig.hpp"
#include "../Store.hpp"

#include <chen/log/log.h>
#include <chen/util/json_util.h>
#include <chen/util/random_util.h>
#include <chen/util/string_util.h>

namespace auth {

static chen::Logger::ptr logger = LOG_NAME("auth");

AuthorizationServlet::AuthorizationServlet() : AuthServlet("AuthorizationServlet") {}

int32_t AuthorizationServlet::handle(chen::http::HttpRequest::ptr request, chen::http::HttpResponse::ptr response
        , chen::http::HttpSession::ptr session, Result::ptr result) {
    // ========== 1. 读取请求参数 ==========
    std::string responseType = request->getParam("response_type");
    std::string clientId = request->getParam("client_id");
    std::string redirectUri = request->getParam("redirect_uri");
    std::string scope = request->getParam("scope");
    std::string state = request->getParam("state");

    // ========== 2. 参数校验 ==========
    if (responseType != "code") {
        ERROR(logger) << "unsupported response_type: " << responseType;
        result->setResult(400, "unsupported_response_type");
        response->setBody(result->toJsonString());
        response->setStatus(chen::http::HttpStatus::BAD_REQUEST);
        return 0;
    }

    if (clientId.empty()) {
        ERROR(logger) << "client_id is required";
        result->setResult(400, "invalid_request");
        result->set("error_description", "client_id required");
        response->setBody(result->toJsonString());
        response->setStatus(chen::http::HttpStatus::BAD_REQUEST);
        return 0;
    }

    // 校验 client_id
    Json::Value client = ClientStore::findByClientId(clientId);
    if (client.isNull()) {
        ERROR(logger) << "invalid client_id: " << clientId;
        result->setResult(401, "invalid_client");
        response->setBody(result->toJsonString());
        response->setStatus(chen::http::HttpStatus::UNAUTHORIZED);
        return 0;
    }

    // 校验 redirect_uri
    if (!redirectUri.empty() && !ClientStore::validateRedirectUri(clientId, redirectUri)) {
        ERROR(logger) << "redirect_uri mismatch for client=" << clientId << ", uri=" << redirectUri;
        result->setResult(400, "invalid_redirect_uri");
        response->setBody(result->toJsonString());
        response->setStatus(chen::http::HttpStatus::BAD_REQUEST);
        return 0;
    }

    // 如果没传 redirect_uri，取客户端注册的第一个
    if (redirectUri.empty()) {
        Json::Value uris;
        if (chen::JsonUtil::FromString(uris, client["redirect_uris"].asString()) && uris.isArray() && uris.size() > 0) {
            redirectUri = uris[0u].asString();
        }
    }

    // scope 必须包含 openid
    bool hasOpenid = false;
    auto scopes = chen::StringUtil::Split(scope, ' ');
    for (auto& s : scopes) {
        if (s == "openid") {
            hasOpenid = true;
            break;
        }
    }
    if (!hasOpenid) {
        ERROR(logger) << "scope must include openid";
        // 有合法的 redirect_uri 时重定向回客户端并带错误
        std::string errUrl = redirectUri + "?error=invalid_scope";
        if (!state.empty()) {
            errUrl += "&state=" + chen::StringUtil::UrlEncode(state);
        }
        response->setRedirect(errUrl);
        response->setStatus(chen::http::HttpStatus::FOUND);
        return 0;
    }

    // ========== 3. 检查用户会话 ==========
    std::string sid = request->getCookie("SESSIONID");
    Json::Value sessionData;
    if (!sid.empty()) {
        sessionData = SessionStore::getSession(sid);
    }

    if (sessionData.isNull()) {
        // 未登录，重定向到登录页面，登录成功后再回到这里
        std::string currentPath = request->getPath();
        if (!request->getQuery().empty()) {
            currentPath += "?" + request->getQuery();
        }
        std::string loginUrl = "/login?redirect=" + chen::StringUtil::UrlEncode(currentPath);
        INFO(logger) << "no session, redirect to login: " << loginUrl;

        response->setRedirect(loginUrl);
        response->setStatus(chen::http::HttpStatus::FOUND);
        return 0;
    }

    // ========== 4. 已登录，生成授权码 ==========
    std::string code = chen::StringUtil::ToLower(chen::StringUtil::HexEncode(chen::RandomUtil::RandBytes(16)));

    Json::Value codeData;
    codeData["client_id"] = clientId;
    codeData["user_id"] = sessionData["userId"];
    codeData["username"] = sessionData["username"];
    codeData["redirect_uri"] = redirectUri;
    codeData["scope"] = scope;
    codeData["nonce"] = request->getParam("nonce");
    std::string codeJson = chen::JsonUtil::ToString(codeData);

    if (!AuthCodeStore::save(code, codeJson, OidcConfig::s_authCodeTtl)) {
        ERROR(logger) << "failed to save auth code to redis";
        result->setResult(500, "server_error");
        response->setBody(result->toJsonString());
        response->setStatus(chen::http::HttpStatus::INTERNAL_SERVER_ERROR);
        return 0;
    }

    // ========== 5. 重定向回客户端 ==========
    std::string location = redirectUri + "?code=" + chen::StringUtil::UrlEncode(code);
    if (!state.empty()) {
        location += "&state=" + chen::StringUtil::UrlEncode(state);
    }
    INFO(logger) << "auth code issued, redirect to: " << redirectUri;

    response->setRedirect(location);
    response->setStatus(chen::http::HttpStatus::FOUND);
    return 0;
}

} // namespace auth
