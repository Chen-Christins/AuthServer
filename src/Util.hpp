/**
 * @file Util.hpp
 * @brief 工具函数头文件
 * @author Christins (chen.christins@qq.com)
 * @date 2026-06-29
 * @copyright Apache 2.0
 */
#pragma once

#include <chen/db/mysql.h>
#include <chen/db/redis.h>

namespace auth {

inline chen::IDB::ptr GetDB() {
    auto db = chen::MySQLMgr::GetInstance()->get("auth");
    if (!db) {
        throw std::runtime_error("GetDB: get mysql conn failed");
    }
    return db;
}

inline chen::IRedis::ptr GetRedis() {
    auto rds = chen::RedisMgr::GetInstance()->get("auth");
    if (!rds) {
        throw std::runtime_error("GetRedis: get redis conn failed");
    }
    return rds;
}

} // namespace auth