/**
 * @file OidcConfig.hpp
 * @brief OIDC 运行时配置
 * @author Christins (chen.christins@qq.com)
 * @date 2026-06-29
 * @copyright Apache 2.0
 */
#pragma once

#include <string>

namespace auth {

struct OidcConfig {
    static std::string s_issuer;
    static std::string s_privateKeyPem;
    static std::string s_publicKeyPem;
    static std::string s_kid;
    static int s_accessTokenTtl;
    static int s_idTokenTtl;
    static int s_refreshTokenTtl;
    static int s_authCodeTtl;
    static int s_sessionTtl;

    static void init();
};

} // namespace auth
