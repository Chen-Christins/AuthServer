/**
 * @file TotpUtil.hpp
 * @brief TOTP 双因素认证工具（RFC 6238 / RFC 4226）
 * @author Christins
 * @date 2026-09-14
 * @copyright Apache 2.0
 */
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace auth {

class TotpUtil {
public:
    /// 生成随机 Base32 编码的 TOTP 密钥（20 字节）
    static std::string GenerateSecret();

    /// 验证 TOTP 验证码（允许前后 window 个时间步容差）
    static bool VerifyCode(const std::string& secret, const std::string& code, int window = 1);

    /// 生成 otpauth:// URI（可转 QR 码）
    static std::string GetOtpUri(const std::string& secret, const std::string& account,
                                 const std::string& issuer = "AuthServer");

    /// 生成恢复码，同时返回哈希列表
    static std::vector<std::string> GenerateRecoveryCodes(int count, std::vector<std::string>& hashedCodes);

    /// 对恢复码做 SHA-256 哈希
    static std::string HashRecoveryCode(const std::string& code);

private:
    static std::string Base32Encode(const uint8_t* data, size_t len);
    static std::vector<uint8_t> Base32Decode(const std::string& encoded);
    static std::string HmacSha1(const std::string& key, const std::string& message);
    static uint32_t DynamicTruncation(const std::string& hmacResult);
    static uint32_t GenerateTotp(const std::string& secret, int64_t timeStep);
};

} // namespace auth
