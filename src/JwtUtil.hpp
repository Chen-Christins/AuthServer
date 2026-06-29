/**
 * @file JwtUtil.hpp
 * @brief JWT 创建/验签工具（RS256），支持 JWK 导出
 * @author Christins (chen.christins@qq.com)
 * @date 2026-06-29
 * @copyright Apache 2.0
 */
#pragma once

#include <json/json.h>
#include <string>

namespace auth {

class JwtUtil {
public:
    /**
     * @brief 创建 RS256 签名的 JWT（自动构造 header）
     * @param payloadJson    payload JSON 字符串
     * @param kid            密钥 ID（空串则 header 不含 kid）
     * @param privateKeyPem  PEM 格式 RSA 私钥
     * @return 完整 JWT，失败返回空串
     */
    static std::string createJWT(const std::string& payloadJson, const std::string& kid,
                                 const std::string& privateKeyPem);

    /**
     * @brief 验证 JWT 签名并解析 payload
     * @param jwt           完整 JWT 字符串
     * @param publicKeyPem  PEM 格式 RSA 公钥
     * @param[out] payload  解析后的 payload
     * @return bool 是否通过
     */
    static bool verifyJWT(const std::string& jwt, const std::string& publicKeyPem, Json::Value& payload);

    /**
     * @brief 从 RSA 公钥 PEM 导出 JWK
     * @param publicKeyPem  PEM 格式 RSA 公钥
     * @param kid           密钥 ID
     * @return JWK JSON，失败返回 Json::nullValue
     */
    static Json::Value extractJWK(const std::string& publicKeyPem, const std::string& kid);

    /**
     * @brief 从 RSA 公钥 PEM 导出 JWKS（JWK Set）
     * @param publicKeyPem  PEM 格式 RSA 公钥
     * @param kid           密钥 ID
     * @return JWKS JSON 字符串，失败返回 "{}"
     */
    static std::string extractJWKS(const std::string& publicKeyPem, const std::string& kid);
};

} // namespace auth
