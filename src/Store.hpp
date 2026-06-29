/**
 * @file Store.hpp
 * @brief 数据存储层：User、Client、AuthCode、RefreshToken
 * @author Christins (chen.christins@qq.com)
 * @date 2026-06-29
 * @copyright Apache 2.0
 */
#pragma once

#include <json/json.h>
#include <string>

namespace auth {

/**
 * @brief 用户存储（MySQL）
 */
class UserStore {
public:
    /**
     * @brief 按用户名查找用户
     * @param username 用户名
     * @return 用户 JSON，未找到返回 null
     */
    static Json::Value findByUsername(const std::string& username);

    /**
     * @brief 核验密码
     * @param username 用户名
     * @param password 明文密码
     * @return 用户 JSON，失败返回 null
     */
    static Json::Value verifyPassword(const std::string& username, const std::string& password);
};

/**
 * @brief OAuth 客户端存储（MySQL）
 */
class ClientStore {
public:
    /**
     * @brief 按 client_id 查找客户端
     * @param clientId 客户端 ID
     * @return 客户端 JSON，未找到返回 null
     */
    static Json::Value findByClientId(const std::string& clientId);

    /**
     * @brief 校验 redirect_uri 是否在白名单内
     * @param clientId  客户端 ID
     * @param redirectUri 重定向 URI
     * @return bool
     */
    static bool validateRedirectUri(const std::string& clientId, const std::string& redirectUri);
};

/**
 * @brief 授权码存储（Redis，自动 TTL）
 */
class AuthCodeStore {
public:
    /**
     * @brief 保存授权码
     * @param code  授权码
     * @param data  JSON 字符串（client_id, user_id, redirect_uri, scope, nonce 等）
     * @param ttl   过期秒数（默认 300 = 5 分钟）
     * @return bool
     */
    static bool save(const std::string& code, const std::string& data, int ttl = 300);

    /**
     * @brief 消费授权码（读取后立即删除，一次性使用）
     * @param code 授权码
     * @return 关联数据 JSON，不存在或已消费返回 null
     */
    static Json::Value consume(const std::string& code);
};

/**
 * @brief Refresh Token 存储（Redis）
 */
class RefreshTokenStore {
public:
    /**
     * @brief 保存 refresh token
     * @param token refresh token
     * @param data  JSON 字符串
     * @param ttl   过期秒数（默认 2592000 = 30 天）
     * @return bool
     */
    static bool save(const std::string& token, const std::string& data, int ttl = 2592000);

    /**
     * @brief 消费 refresh token（读取后立即删除，支持轮换）
     * @param token refresh token
     * @return 关联数据 JSON，无效或已消费返回 null
     */
    static Json::Value consume(const std::string& token);

    /**
     * @brief 撤销 refresh token
     * @param token refresh token
     */
    static void revoke(const std::string& token);
};

/**
 * @brief 用户会话存储（Redis）
 */
class SessionStore {
public:
    /**
     * @brief 创建会话
     * @param userId   用户 ID
     * @param username 用户名
     * @param ttl      过期秒数
     * @return 会话 ID（随机 hex 字符串），失败返回空串
     */
    static std::string createSession(int64_t userId, const std::string& username, int ttl = 86400);

    /**
     * @brief 获取会话信息
     * @param sessionId 会话 ID
     * @return 会话 JSON {id, userId, username}，不存在返回 null
     */
    static Json::Value getSession(const std::string& sessionId);

    /**
     * @brief 销毁会话
     * @param sessionId 会话 ID
     */
    static void destroySession(const std::string& sessionId);
};

} // namespace auth
