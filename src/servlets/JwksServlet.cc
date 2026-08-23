#include "JwksServlet.hpp"

#include "../JwtUtil.hpp"
#include "../OidcConfig.hpp"

#include <chen/log/log.h>
#include <chen/util/json_util.h>

namespace auth {

static chen::Logger::ptr logger = LOG_NAME("auth");

static chen::ConfigVar<AuthConf>::ptr g_auth_conf =
    chen::Config::Lookup("auth", AuthConf(), "auth configuration");

JwksServlet::JwksServlet() : AuthServlet("JwksServlet") {}

int32_t JwksServlet::handle(chen::http::HttpRequest::ptr request, chen::http::HttpResponse::ptr response
        , chen::http::HttpSession::ptr session, Result::ptr result) {
    const std::string& kid = g_auth_conf->getValue().key.kid;
    const std::string& public_key_path = g_auth_conf->getValue().key.public_key_path;
    const std::string& public_key_pem = chen::FSUtil::ReadFileToString(public_key_path);

    if (public_key_pem.empty()) {
        ERROR(logger) << "public key not loaded";
        result->setResult(500, "server_config_error");
        response->setBody(result->toJsonString());
        response->setStatus(chen::http::HttpStatus::INTERNAL_SERVER_ERROR);
        return 0;
    }

    // JWKS JSON 解析后放入 data 层
    Json::Value jwks;
    chen::JsonUtil::FromString(jwks, JwtUtil::extractJWKS(public_key_pem, kid));
    result->setResult(200, "ok");
    result->set("keys", jwks["keys"]);

    response->setBody(result->toJsonString());
    response->setStatus(chen::http::HttpStatus::OK);
    return 0;
}

} // namespace auth
