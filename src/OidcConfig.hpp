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
    static std::string issuer;
    static std::string privateKeyPem;
    static std::string publicKeyPem;
    static std::string kid;
    static int accessTokenTtl;
    static int idTokenTtl;
    static int refreshTokenTtl;
    static int authCodeTtl;
    static int sessionTtl;

    static void init();
};

} // namespace auth
