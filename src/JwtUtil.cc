#include "JwtUtil.hpp"

#include <chen/log/log.h>
#include <chen/util/encryptor_util.h>
#include <chen/util/json_util.h>
#include <chen/util/string_util.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <vector>

namespace auth {

static chen::Logger::ptr logger = LOG_NAME("auth");

std::string JwtUtil::createJWT(const std::string& payloadJson, const std::string& kid
        , const std::string& privateKeyPem) {
    Json::Value header;
    header["alg"] = "RS256";
    header["typ"] = "JWT";
    if (!kid.empty()) {
        header["kid"] = kid;
    }

    std::string headerJson = chen::JsonUtil::ToString(header);
    if (headerJson.empty()) {
        ERROR(logger) << "createJWT: header to string failed";
        return "";
    }

    std::string h = chen::StringUtil::Base64UrlEncode(headerJson);
    std::string p = chen::StringUtil::Base64UrlEncode(payloadJson);
    std::string input = h + "." + p;

    std::string sig = chen::EncryptorUtil::RS256Sign(input, privateKeyPem);
    if (sig.empty()) {
        ERROR(logger) << "createJWT: RS256Sign failed";
        return "";
    }

    return h + "." + p + "." + chen::StringUtil::Base64UrlEncode(sig);
}

bool JwtUtil::verifyJWT(const std::string& jwt, const std::string& publicKeyPem, Json::Value& payload) {
    auto parts = chen::StringUtil::Split(jwt, '.');
    if (parts.size() != 3) {
        ERROR(logger) << "verifyJWT: invalid JWT format, parts=" << parts.size();
        return false;
    }

    std::string input = parts[0] + "." + parts[1];
    std::string sig = chen::StringUtil::Base64UrlDecode(parts[2]);
    if (sig.empty()) {
        ERROR(logger) << "verifyJWT: base64 decode signature failed";
        return false;
    }

    if (!chen::EncryptorUtil::RS256Verify(input, sig, publicKeyPem)) {
        WARN(logger) << "verifyJWT: signature mismatch";
        return false;
    }

    std::string payloadJson = chen::StringUtil::Base64UrlDecode(parts[1]);
    if (!chen::JsonUtil::FromString(payload, payloadJson)) {
        ERROR(logger) << "verifyJWT: parse payload failed";
        return false;
    }

    return true;
}

Json::Value JwtUtil::extractJWK(const std::string& publicKeyPem, const std::string& kid) {
    BIO* bio = BIO_new_mem_buf(publicKeyPem.data(), static_cast<int>(publicKeyPem.size()));
    if (!bio) {
        ERROR(logger) << "extractJWK: BIO_new_mem_buf failed";
        return Json::nullValue;
    }

    EVP_PKEY* evp = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!evp) {
        ERROR(logger) << "extractJWK: PEM_read_bio_PUBKEY failed";
        return Json::nullValue;
    }

    RSA* rsa = EVP_PKEY_get1_RSA(evp);
    if (!rsa) {
        ERROR(logger) << "extractJWK: EVP_PKEY_get1_RSA failed";
        EVP_PKEY_free(evp);
        return Json::nullValue;
    }

    const BIGNUM* n = nullptr;
    const BIGNUM* e = nullptr;
    RSA_get0_key(rsa, &n, &e, nullptr);

    int nLen = BN_num_bytes(n);
    int eLen = BN_num_bytes(e);
    std::vector<unsigned char> nBuf(nLen);
    std::vector<unsigned char> eBuf(eLen);
    BN_bn2bin(n, nBuf.data());
    BN_bn2bin(e, eBuf.data());

    RSA_free(rsa);
    EVP_PKEY_free(evp);

    Json::Value jwk;
    jwk["kty"] = "RSA";
    jwk["n"] = chen::StringUtil::Base64UrlEncode(std::string(reinterpret_cast<const char*>(nBuf.data()), nBuf.size()));
    jwk["e"] = chen::StringUtil::Base64UrlEncode(std::string(reinterpret_cast<const char*>(eBuf.data()), eBuf.size()));
    jwk["alg"] = "RS256";
    jwk["use"] = "sig";
    if (!kid.empty()) {
        jwk["kid"] = kid;
    }
    return jwk;
}

std::string JwtUtil::extractJWKS(const std::string& publicKeyPem, const std::string& kid) {
    Json::Value jwk = extractJWK(publicKeyPem, kid);
    if (jwk.isNull()) {
        return "{}";
    }
    Json::Value jwks;
    jwks["keys"].append(jwk);
    return chen::JsonUtil::ToString(jwks);
}

} // namespace auth
