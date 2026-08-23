#include "LoginServlet.hpp"

#include "../OidcConfig.hpp"
#include "../Store.hpp"

#include <chen/log/log.h>
#include <chen/util/json_util.h>

namespace auth {

static chen::Logger::ptr logger = LOG_NAME("auth");

static chen::ConfigVar<AuthConf>::ptr g_auth_conf =
    chen::Config::Lookup("auth", AuthConf(), "auth configuration");

LoginServlet::LoginServlet() : AuthServlet("LoginServlet") {}

int32_t LoginServlet::handle(chen::http::HttpRequest::ptr request, chen::http::HttpResponse::ptr response
        , chen::http::HttpSession::ptr session, Result::ptr result) {
    if (request->getMethod() != chen::http::HttpMethod::POST) {
        response->setStatus(chen::http::HttpStatus::METHOD_NOT_ALLOWED);
        return 0;
    }
    return handlePost(request, response, result);
}

int32_t LoginServlet::handlePost(chen::http::HttpRequest::ptr request, chen::http::HttpResponse::ptr response, Result::ptr result) {
    // 解析 JSON body
    std::string body = request->getBody();
    Json::Value json;
    if (!chen::JsonUtil::FromString(json, body)) {
        result->setResult(400, "invalid_request");
        result->set("error_description", "invalid JSON body");
        response->setBody(result->toJsonString());
        response->setStatus(chen::http::HttpStatus::BAD_REQUEST);
        return 0;
    }

    std::string username = json.get("username", "").asString();
    std::string password = json.get("password", "").asString();

    if (username.empty() || password.empty()) {
        result->setResult(400, "invalid_request");
        result->set("error_description", "username and password required");
        response->setBody(result->toJsonString());
        response->setStatus(chen::http::HttpStatus::BAD_REQUEST);
        return 0;
    }

    // 校验凭据
    Json::Value user = UserStore::verifyPassword(username, password);
    if (user.isNull()) {
        WARN(logger) << "login failed for user=" << username;
        result->setResult(401, "login_failed");
        result->set("error_description", "invalid username or password");
        response->setBody(result->toJsonString());
        response->setStatus(chen::http::HttpStatus::UNAUTHORIZED);
        return 0;
    }

    int session_ttl = g_auth_conf->getValue().session_ttl;
    // 创建会话
    std::string sid = SessionStore::createSession(user["id"].asInt64(), user["username"].asString(), session_ttl);
    if (sid.empty()) {
        ERROR(logger) << "create session failed";
        result->setResult(500, "server_error");
        response->setBody(result->toJsonString());
        response->setStatus(chen::http::HttpStatus::INTERNAL_SERVER_ERROR);
        return 0;
    }

    // 设置 SESSIONID cookie
    std::string cookie = "SESSIONID=" + sid + "; HttpOnly; SameSite=Lax; Path=/; Max-Age=" + std::to_string(session_ttl);
    response->setHeader("Set-Cookie", cookie);

    INFO(logger) << "login success user=" << username;
    result->setResult(200, "ok");
    result->set("session_id", sid);
    response->setBody(result->toJsonString());
    response->setStatus(chen::http::HttpStatus::OK);
    return 0;
}

} // namespace auth
