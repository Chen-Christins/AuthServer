#include "OidcConfig.hpp"

#include <chen/config/config.h>
#include <chen/log/log.h>
#include <chen/util/fs_util.h>

namespace auth {

static chen::Logger::ptr logger = LOG_NAME("auth");

static chen::ConfigVar<std::string>::ptr g_issuer = 
    chen::Config::Lookup<std::string>("auth.issuer", "http://localhost:8080", "OIDC issuer");
static chen::ConfigVar<std::string>::ptr g_kid = 
    chen::Config::Lookup<std::string>("auth.key.kid", "rsa1", "OIDC key ID");
static chen::ConfigVar<int>::ptr g_access_token_ttl = 
    chen::Config::Lookup<int>("auth.token.access_token_ttl", 3600, "Access token TTL in seconds");
static chen::ConfigVar<int>::ptr g_id_token_ttl = 
    chen::Config::Lookup<int>("auth.token.id_token_ttl", 3600, "ID token TTL in seconds");
static chen::ConfigVar<int>::ptr g_refresh_token_ttl = 
    chen::Config::Lookup<int>("auth.token.refresh_token_ttl", 2592000, "Refresh token TTL in seconds");
static chen::ConfigVar<int>::ptr g_auth_code_ttl = 
    chen::Config::Lookup<int>("auth.token.auth_code_ttl", 300, "Authorization code TTL in seconds");
static chen::ConfigVar<int>::ptr g_session_ttl = 
    chen::Config::Lookup<int>("auth.session_ttl", 86400, "Session TTL in seconds");
static chen::ConfigVar<std::string>::ptr g_private_key_path = 
    chen::Config::Lookup<std::string>("auth.key.private_key_path", "", "Path to RSA private key PEM file");
static chen::ConfigVar<std::string>::ptr g_public_key_path = 
    chen::Config::Lookup<std::string>("auth.key.public_key_path", "", "Path to RSA public key PEM file");

std::string OidcConfig::s_issuer;
std::string OidcConfig::s_privateKeyPem;
std::string OidcConfig::s_publicKeyPem;
std::string OidcConfig::s_kid;
int OidcConfig::s_accessTokenTtl = 3600;
int OidcConfig::s_idTokenTtl = 3600;
int OidcConfig::s_refreshTokenTtl = 2592000;
int OidcConfig::s_authCodeTtl = 300;
int OidcConfig::s_sessionTtl = 86400;

void OidcConfig::init() {
    s_issuer = g_issuer->getValue();
    if (s_issuer.empty()) {
        s_issuer = "http://localhost:8080";
        WARN(logger) << "auth.issuer not configured, using default: " << s_issuer;
    }

    s_kid = g_kid->getValue();
    s_accessTokenTtl = g_access_token_ttl->getValue();
    s_idTokenTtl = g_id_token_ttl->getValue();
    s_refreshTokenTtl = g_refresh_token_ttl->getValue();
    s_authCodeTtl = g_auth_code_ttl->getValue();
    s_sessionTtl = g_session_ttl->getValue();
    std::string privPath = g_private_key_path->getValue();
    std::string pubPath = g_public_key_path->getValue();

    if (privPath.empty() || pubPath.empty()) {
        ERROR(logger) << "auth.key.private_key_path or public_key_path" << " not configured";
        return;
    }

    s_privateKeyPem = chen::FSUtil::ReadFileToString(privPath);
    s_publicKeyPem = chen::FSUtil::ReadFileToString(pubPath);

    if (s_privateKeyPem.empty() || s_publicKeyPem.empty()) {
        ERROR(logger) << "failed to read RSA key files";
        return;
    }

    INFO(logger) << "OIDC config loaded: issuer=" << s_issuer 
        << " kid=" << s_kid << " at_ttl=" << s_accessTokenTtl << " rt_ttl=" << s_refreshTokenTtl;
}

} // namespace auth
