#include "JwksServlet.hpp"

#include "../JwtUtil.hpp"
#include "../OidcConfig.hpp"

#include <chen/log/log.h>

namespace auth {

static chen::Logger::ptr logger = LOG_NAME("auth.jwks");

JwksServlet::JwksServlet() : AuthServlet("JwksServlet") {}

int32_t JwksServlet::handle(chen::http::HttpRequest::ptr request, chen::http::HttpResponse::ptr response
        , chen::http::HttpSession::ptr session, Result::ptr result) {
    if (OidcConfig::publicKeyPem.empty()) {
        ERROR(logger) << "public key not loaded";
        response->setBody("{\"error\":\"server_config_error\"}");
        response->setHeader("Content-Type", "application/json");
        response->setStatus(chen::http::HttpStatus::INTERNAL_SERVER_ERROR);
        return 0;
    }

    std::string jwks = JwtUtil::extractJWKS(OidcConfig::publicKeyPem, OidcConfig::kid);

    response->setBody(jwks);
    response->setHeader("Content-Type", "application/json");
    response->setStatus(chen::http::HttpStatus::OK);
    return 0;
}

} // namespace auth
