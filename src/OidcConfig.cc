#include "OidcConfig.hpp"

#include <chen/config/config.h>
#include <chen/log/log.h>
#include <chen/util/fs_util.h>

namespace auth {

static chen::Logger::ptr logger = LOG_NAME("auth.config");

std::string OidcConfig::issuer;
std::string OidcConfig::privateKeyPem;
std::string OidcConfig::publicKeyPem;
std::string OidcConfig::kid;
int OidcConfig::accessTokenTtl = 3600;
int OidcConfig::idTokenTtl = 3600;
int OidcConfig::refreshTokenTtl = 2592000;
int OidcConfig::authCodeTtl = 300;
int OidcConfig::sessionTtl = 86400;

void OidcConfig::init() {
    auto cfgIssuer = chen::Config::Lookup<std::string>("auth.issuer");
    if (cfgIssuer) {
        issuer = cfgIssuer->getValue();
    }
    if (issuer.empty()) {
        issuer = "http://localhost:8080";
        WARN(logger) << "auth.issuer not configured, using default: " << issuer;
    }

    auto cfgKid = chen::Config::Lookup<std::string>("auth.key.kid");
    if (cfgKid) {
        kid = cfgKid->getValue();
    }
    if (kid.empty()) {
        kid = "rsa1";
    }

    auto cfgATtl = chen::Config::Lookup<int>("auth.token.access_token_ttl");
    if (cfgATtl) {
        accessTokenTtl = cfgATtl->getValue();
    }

    auto cfgITtl = chen::Config::Lookup<int>("auth.token.id_token_ttl");
    if (cfgITtl) {
        idTokenTtl = cfgITtl->getValue();
    }

    auto cfgRTtl = chen::Config::Lookup<int>("auth.token.refresh_token_ttl");
    if (cfgRTtl) {
        refreshTokenTtl = cfgRTtl->getValue();
    }

    auto cfgCTtl = chen::Config::Lookup<int>("auth.token.auth_code_ttl");
    if (cfgCTtl) {
        authCodeTtl = cfgCTtl->getValue();
    }

    auto cfgSTtl = chen::Config::Lookup<int>("auth.session_ttl");
    if (cfgSTtl) {
        sessionTtl = cfgSTtl->getValue();
    }

    // 读取密钥文件路径配置
    auto cfgPrivPath = chen::Config::Lookup<std::string>("auth.key.private_key_path");
    auto cfgPubPath = chen::Config::Lookup<std::string>("auth.key.public_key_path");

    std::string privPath = cfgPrivPath ? cfgPrivPath->getValue() : "";
    std::string pubPath = cfgPubPath ? cfgPubPath->getValue() : "";

    if (privPath.empty() || pubPath.empty()) {
        ERROR(logger) << "auth.key.private_key_path or public_key_path" << " not configured";
        return;
    }

    privateKeyPem = chen::FSUtil::ReadFileToString(privPath);
    publicKeyPem = chen::FSUtil::ReadFileToString(pubPath);

    if (privateKeyPem.empty() || publicKeyPem.empty()) {
        ERROR(logger) << "failed to read RSA key files";
        return;
    }

    INFO(logger) << "OIDC config loaded: issuer=" << issuer << " kid=" << kid << " at_ttl=" << accessTokenTtl
                 << " rt_ttl=" << refreshTokenTtl;
}

} // namespace auth
