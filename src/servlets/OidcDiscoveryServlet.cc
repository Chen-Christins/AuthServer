#include "OidcDiscoveryServlet.hpp"

#include "../OidcConfig.hpp"

#include <chen/log/log.h>
#include <chen/util/json_util.h>

namespace auth {

static chen::Logger::ptr logger = LOG_NAME("auth.discovery");

OidcDiscoveryServlet::OidcDiscoveryServlet() : AuthServlet("OidcDiscoveryServlet") {}

int32_t OidcDiscoveryServlet::handle(chen::http::HttpRequest::ptr request, chen::http::HttpResponse::ptr response
        , chen::http::HttpSession::ptr session, Result::ptr result) {
    std::string iss = OidcConfig::issuer;

    Json::Value doc;
    doc["issuer"] = iss;
    doc["authorization_endpoint"] = iss + "/authorize";
    doc["token_endpoint"] = iss + "/token";
    doc["userinfo_endpoint"] = iss + "/userinfo";
    doc["jwks_uri"] = iss + "/jwks.json";
    doc["scopes_supported"].append("openid");
    doc["scopes_supported"].append("profile");
    doc["scopes_supported"].append("email");
    doc["response_types_supported"].append("code");
    doc["response_modes_supported"].append("query");
    doc["response_modes_supported"].append("form_post");
    doc["grant_types_supported"].append("authorization_code");
    doc["grant_types_supported"].append("refresh_token");
    doc["subject_types_supported"].append("public");
    doc["id_token_signing_alg_values_supported"].append("RS256");
    doc["token_endpoint_auth_methods_supported"].append("client_secret_basic");
    doc["token_endpoint_auth_methods_supported"].append("client_secret_post");
    doc["claims_supported"].append("sub");
    doc["claims_supported"].append("iss");
    doc["claims_supported"].append("aud");
    doc["claims_supported"].append("exp");
    doc["claims_supported"].append("iat");
    doc["claims_supported"].append("auth_time");
    doc["claims_supported"].append("name");
    doc["claims_supported"].append("preferred_username");
    doc["claims_supported"].append("email");
    doc["claims_supported"].append("email_verified");
    doc["claims_parameter_supported"] = false;
    doc["request_parameter_supported"] = false;
    doc["request_uri_parameter_supported"] = false;

    std::string body = chen::JsonUtil::ToString(doc);
    response->setBody(body);
    response->setHeader("Content-Type", "application/json");
    response->setStatus(chen::http::HttpStatus::OK);
    return 0;
}

} // namespace auth
