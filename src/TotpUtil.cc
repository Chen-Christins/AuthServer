#include "TotpUtil.hpp"

#include <chen/util/encryptor_util.h>
#include <chen/util/random_util.h>
#include <chen/util/string_util.h>

#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <algorithm>
#include <cstring>
#include <ctime>
#include <random>
#include <sstream>

namespace auth {

static const int kTimeStep = 30;
static const int kDigits = 6;
static const char kBase32Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
static const char kRecoveryChars[] = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

std::string TotpUtil::GenerateSecret() {
    std::string randomData = chen::RandomUtil::RandBytes(20);
    return Base32Encode(reinterpret_cast<const uint8_t*>(randomData.data()), randomData.size());
}

std::string TotpUtil::Base32Encode(const uint8_t* data, size_t len) {
    std::string result;
    int bits = 0;
    uint32_t value = 0;

    for (size_t i = 0; i < len; ++i) {
        value = (value << 8) | data[i];
        bits += 8;
        while (bits >= 5) {
            result += kBase32Alphabet[(value >> (bits - 5)) & 0x1F];
            bits -= 5;
        }
    }
    if (bits > 0) {
        result += kBase32Alphabet[(value << (5 - bits)) & 0x1F];
    }
    while (result.size() % 8 != 0) {
        result += '=';
    }
    return result;
}

std::vector<uint8_t> TotpUtil::Base32Decode(const std::string& encoded) {
    std::vector<uint8_t> result;
    int bits = 0;
    uint32_t value = 0;

    for (char c : encoded) {
        if (c == '=' || c == ' ') {
            continue;
        }
        int idx = -1;
        if (c >= 'A' && c <= 'Z') {
            idx = c - 'A';
        } else if (c >= '2' && c <= '7') {
            idx = c - '2' + 26;
        } else if (c >= 'a' && c <= 'z') {
            idx = c - 'a';
        }
        if (idx < 0) {
            continue;
        }
        value = (value << 5) | idx;
        bits += 5;
        if (bits >= 8) {
            result.push_back(static_cast<uint8_t>((value >> (bits - 8)) & 0xFF));
            bits -= 8;
        }
    }
    return result;
}

std::string TotpUtil::HmacSha1(const std::string& key, const std::string& message) {
    unsigned char digest[SHA_DIGEST_LENGTH];
    unsigned int len = SHA_DIGEST_LENGTH;
    HMAC(EVP_sha1(),
         key.data(), key.size(),
         reinterpret_cast<const unsigned char*>(message.data()), message.size(),
         digest, &len);
    return std::string(reinterpret_cast<char*>(digest), len);
}

uint32_t TotpUtil::DynamicTruncation(const std::string& hmacResult) {
    if (hmacResult.size() < 20) {
        return 0;
    }
    int offset = hmacResult[19] & 0x0F;
    uint32_t code = (static_cast<uint32_t>(hmacResult[offset] & 0x7F) << 24)
                  | (static_cast<uint32_t>(hmacResult[offset + 1] & 0xFF) << 16)
                  | (static_cast<uint32_t>(hmacResult[offset + 2] & 0xFF) << 8)
                  | (static_cast<uint32_t>(hmacResult[offset + 3] & 0xFF));
    return code;
}

uint32_t TotpUtil::GenerateTotp(const std::string& secret, int64_t timeStep) {
    uint8_t timeBytes[8];
    uint64_t t = static_cast<uint64_t>(timeStep);
    for (int i = 7; i >= 0; --i) {
        timeBytes[i] = t & 0xFF;
        t >>= 8;
    }
    std::string timeMessage(reinterpret_cast<char*>(timeBytes), 8);

    std::vector<uint8_t> secretBytes = Base32Decode(secret);
    std::string key(reinterpret_cast<char*>(secretBytes.data()), secretBytes.size());

    std::string hmac = HmacSha1(key, timeMessage);
    uint32_t truncated = DynamicTruncation(hmac);
    return truncated % (1u << (kDigits * 3));
}

bool TotpUtil::VerifyCode(const std::string& secret, const std::string& code, int window) {
    if (secret.empty() || code.size() != kDigits) {
        return false;
    }
    for (char c : code) {
        if (c < '0' || c > '9') {
            return false;
        }
    }

    int64_t now = time(nullptr);
    int64_t currentTimeStep = now / kTimeStep;

    for (int i = -window; i <= window; ++i) {
        uint32_t expected = GenerateTotp(secret, currentTimeStep + i);
        char expectedStr[8];
        snprintf(expectedStr, sizeof(expectedStr), "%06u", expected);
        if (code == expectedStr) {
            return true;
        }
    }
    return false;
}

std::string TotpUtil::GetOtpUri(const std::string& secret, const std::string& account,
                                 const std::string& issuer) {
    std::stringstream ss;
    ss << "otpauth://totp/"
       << issuer << ":" << account
       << "?secret=" << secret
       << "&issuer=" << issuer
       << "&algorithm=SHA1"
       << "&digits=" << kDigits
       << "&period=" << kTimeStep;
    return ss.str();
}

std::string TotpUtil::HashRecoveryCode(const std::string& code) {
    return chen::EncryptorUtil::SHA256(code);
}

std::vector<std::string> TotpUtil::GenerateRecoveryCodes(int count, std::vector<std::string>& hashedCodes) {
    std::vector<std::string> codes;
    hashedCodes.clear();
    hashedCodes.reserve(count);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, sizeof(kRecoveryChars) - 2);

    for (int i = 0; i < count; ++i) {
        std::string code;
        code.reserve(10);
        for (int j = 0; j < 10; ++j) {
            code += kRecoveryChars[dis(gen)];
        }
        code = code.substr(0, 5) + "-" + code.substr(5);
        codes.push_back(code);
        hashedCodes.push_back(HashRecoveryCode(code));
    }
    return codes;
}

} // namespace auth
