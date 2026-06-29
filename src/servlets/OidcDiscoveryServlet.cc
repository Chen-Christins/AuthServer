#include "OidcDiscoveryServlet.hpp"

#include "../OidcConfig.hpp"

#include <chen/log/log.h>
#include <chen/util/json_util.h>

namespace auth {

static chen::Logger::ptr logger = LOG_NAME("auth");

OidcDiscoveryServlet::OidcDiscoveryServlet() : AuthServlet("OidcDiscoveryServlet") {}

int32_t OidcDiscoveryServlet::handle(chen::http::HttpRequest::ptr request, chen::http::HttpResponse::ptr response
        , chen::http::HttpSession::ptr session, Result::ptr result) {
    std::string iss = OidcConfig::s_issuer;

    result->setResult(200, "ok");
    result->set("issuer", iss);
    result->set("authorization_endpoint", iss + "/authorize");
    result->set("token_endpoint", iss + "/token");
    result->set("userinfo_endpoint", iss + "/userinfo");
    result->set("jwks_uri", iss + "/jwks.json");
    result->append("scopes_supported", "openid");
    result->append("scopes_supported", "profile");
    result->append("scopes_supported", "email");
    result->append("response_types_supported", "code");
    result->append("response_modes_supported", "query");
    result->append("response_modes_supported", "form_post");
    result->append("grant_types_supported", "authorization_code");
    result->append("grant_types_supported", "refresh_token");
    result->append("subject_types_supported", "public");
    result->append("id_token_signing_alg_values_supported", "RS256");
    result->append("token_endpoint_auth_methods_supported", "client_secret_basic");
    result->append("token_endpoint_auth_methods_supported", "client_secret_post");
    result->append("claims_supported", "sub");
    result->append("claims_supported", "iss");
    result->append("claims_supported", "aud");
    result->append("claims_supported", "exp");
    result->append("claims_supported", "iat");
    result->append("claims_supported", "auth_time");
    result->append("claims_supported", "name");
    result->append("claims_supported", "preferred_username");
    result->append("claims_supported", "email");
    result->append("claims_supported", "email_verified");
    result->set("claims_parameter_supported", false);
    result->set("request_parameter_supported", false);
    result->set("request_uri_parameter_supported", false);

    response->setBody(result->toJsonString());
    response->setStatus(chen::http::HttpStatus::OK);
    return 0;
}

} // namespace auth
