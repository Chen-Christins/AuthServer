/**
 * @file OidcConfig.hpp
 * @brief OIDC 运行时配置
 * @author Christins (chen.christins@qq.com)
 * @date 2026-06-29
 * @copyright Apache 2.0
 */
#pragma once

#include <chen/config/config.h>

#include <sstream>
#include <string>

namespace auth {

/// OIDC 签名密钥配置
struct KeyConf {
    std::string kid = "rsa1";
    std::string private_key_path;
    std::string public_key_path;

    bool operator==(const KeyConf& oth) const {
        return kid == oth.kid
            && private_key_path == oth.private_key_path
            && public_key_path == oth.public_key_path;
    }
};

/// OIDC Token 有效期配置
struct TokenConf {
    int access_token_ttl = 3600;
    int id_token_ttl = 3600;
    int refresh_token_ttl = 2592000;
    int auth_code_ttl = 300;

    bool operator==(const TokenConf& oth) const {
        return access_token_ttl == oth.access_token_ttl
            && id_token_ttl == oth.id_token_ttl
            && refresh_token_ttl == oth.refresh_token_ttl
            && auth_code_ttl == oth.auth_code_ttl;
    }
};

/// OIDC 认证服务配置
struct AuthConf {
    std::string issuer = "http://localhost:8080";
    int session_ttl = 86400;
    KeyConf key;
    TokenConf token;

    bool isValid() const {
        return !issuer.empty();
    }

    bool operator==(const AuthConf& oth) const {
        return issuer == oth.issuer
            && session_ttl == oth.session_ttl
            && key == oth.key
            && token == oth.token;
    }
};

} // namespace auth

namespace chen {

/**
 * @brief LexicalCast 全特化: std::string -> auth::AuthConf
 */
template <>
class LexicalCast<std::string, auth::AuthConf> {
public:
    auth::AuthConf operator()(const std::string& v) {
        YAML::Node node = YAML::Load(v);
        auth::AuthConf conf;
        conf.issuer = node["issuer"].as<std::string>(conf.issuer);
        conf.session_ttl = node["session_ttl"].as<int>(conf.session_ttl);
        conf.key.kid = node["key"]["kid"].as<std::string>(conf.key.kid);
        conf.key.private_key_path = node["key"]["private_key_path"].as<std::string>(conf.key.private_key_path);
        conf.key.public_key_path = node["key"]["public_key_path"].as<std::string>(conf.key.public_key_path);
        conf.token.access_token_ttl = node["token"]["access_token_ttl"].as<int>(conf.token.access_token_ttl);
        conf.token.id_token_ttl = node["token"]["id_token_ttl"].as<int>(conf.token.id_token_ttl);
        conf.token.refresh_token_ttl = node["token"]["refresh_token_ttl"].as<int>(conf.token.refresh_token_ttl);
        conf.token.auth_code_ttl = node["token"]["auth_code_ttl"].as<int>(conf.token.auth_code_ttl);
        return conf;
    }
};

/**
 * @brief LexicalCast 全特化: auth::AuthConf -> std::string
 */
template <>
class LexicalCast<auth::AuthConf, std::string> {
public:
    std::string operator()(const auth::AuthConf& conf) {
        YAML::Node node;
        node["issuer"] = conf.issuer;
        node["session_ttl"] = conf.session_ttl;

        YAML::Node key;
        key["kid"] = conf.key.kid;
        key["private_key_path"] = conf.key.private_key_path;
        key["public_key_path"] = conf.key.public_key_path;
        node["key"] = key;

        YAML::Node token;
        token["access_token_ttl"] = conf.token.access_token_ttl;
        token["id_token_ttl"] = conf.token.id_token_ttl;
        token["refresh_token_ttl"] = conf.token.refresh_token_ttl;
        token["auth_code_ttl"] = conf.token.auth_code_ttl;
        node["token"] = token;

        std::stringstream ss;
        ss << node;
        return ss.str();
    }
};

} // namespace chen
