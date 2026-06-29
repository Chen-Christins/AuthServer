#include "LoginServlet.hpp"

#include "../OidcConfig.hpp"
#include "../Store.hpp"

#include <chen/log/log.h>
#include <chen/util/string_util.h>

namespace auth {

static chen::Logger::ptr logger = LOG_NAME("auth.login");

LoginServlet::LoginServlet() : AuthServlet("LoginServlet") {}

int32_t LoginServlet::handle(chen::http::HttpRequest::ptr request, chen::http::HttpResponse::ptr response
        , chen::http::HttpSession::ptr session, Result::ptr result) {
    // ========== 分发 GET / POST ==========
    if (request->getMethod() == chen::http::HttpMethod::GET) {
        return handleGet(request, response);
    }
    if (request->getMethod() == chen::http::HttpMethod::POST) {
        return handlePost(request, response, result);
    }

    response->setStatus(chen::http::HttpStatus::METHOD_NOT_ALLOWED);
    return 0;
}

int32_t LoginServlet::handleGet(chen::http::HttpRequest::ptr request, chen::http::HttpResponse::ptr response) {
    std::string redirect = request->getParam("redirect");

    std::string html = R"(<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>登录 - AuthServer</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
     display:flex;justify-content:center;align-items:center;height:100vh;
     margin:0;background:#f5f5f5}
.card{background:#fff;border-radius:8px;padding:40px;box-shadow:0 2px 12px rgba(0,0,0,.1);width:360px}
h2{margin:0 0 24px;text-align:center;color:#333}
label{display:block;margin-bottom:6px;color:#555;font-size:14px}
input[type=text],input[type=password]{width:100%;padding:10px 12px;
  border:1px solid #ddd;border-radius:4px;font-size:15px;box-sizing:border-box;margin-bottom:16px}
button{width:100%;padding:10px;background:#1677ff;color:#fff;border:none;
  border-radius:4px;font-size:16px;cursor:pointer}
button:hover{background:#4096ff}
.error{color:#ff4d4f;font-size:14px;text-align:center;margin-bottom:12px}
</style>
</head>
<body>
<div class="card">
<h2>登录</h2>
)";
    if (request->getParam("error") == "1") {
        html += R"(<div class="error">用户名或密码错误</div>)";
    }
    html += R"(<form method="post" action="/login">
<input type="hidden" name="redirect" value=")" +
            chen::StringUtil::UrlEncode(redirect) + R"(">
<label for="username">用户名</label>
<input type="text" id="username" name="username" placeholder="请输入用户名" required>
<label for="password">密码</label>
<input type="password" id="password" name="password" placeholder="请输入密码" required>
<button type="submit">登 录</button>
</form>
</div>
</body>
</html>)";

    response->setBody(html);
    response->setHeader("Content-Type", "text/html; charset=utf-8");
    response->setStatus(chen::http::HttpStatus::OK);
    return 0;
}

int32_t LoginServlet::handlePost(chen::http::HttpRequest::ptr request, chen::http::HttpResponse::ptr response, Result::ptr result) {
    std::string username = request->getParam("username");
    std::string password = request->getParam("password");
    std::string redirect = request->getParam("redirect");

    // 校验凭据
    Json::Value user = UserStore::verifyPassword(username, password);
    if (user.isNull()) {
        WARN(logger) << "login failed for user=" << username;
        std::string errorUrl = "/login?error=1";
        if (!redirect.empty()) {
            errorUrl += "&redirect=" + chen::StringUtil::UrlEncode(redirect);
        }
        response->setRedirect(errorUrl);
        response->setStatus(chen::http::HttpStatus::FOUND);
        return 0;
    }

    // 创建会话
    std::string sid =
        SessionStore::createSession(user["id"].asInt64(), user["username"].asString(), OidcConfig::sessionTtl);
    if (sid.empty()) {
        ERROR(logger) << "create session failed";
        result->setResult(500, "server_error");
        response->setBody(result->toJsonString());
        response->setStatus(chen::http::HttpStatus::INTERNAL_SERVER_ERROR);
        return 0;
    }

    // 设置 SESSIONID cookie
    std::string cookie =
        "SESSIONID=" + sid + "; HttpOnly; SameSite=Lax; Path=/; Max-Age=" + std::to_string(OidcConfig::sessionTtl);
    response->setHeader("Set-Cookie", cookie);

    // 重定向回去
    if (redirect.empty()) {
        redirect = "/";
    }
    INFO(logger) << "login success user=" << username << ", redirect=" << redirect;
    response->setRedirect(redirect);
    response->setStatus(chen::http::HttpStatus::FOUND);
    return 0;
}

} // namespace auth
