-- ============================================================
-- AuthServer OIDC 数据库初始化脚本
-- 用法: mysql -u root -p < sql/init.sql
-- 然后运行: tools/setup.sh 生成密钥和初始化数据
-- ============================================================

CREATE DATABASE IF NOT EXISTS auth_server
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_unicode_ci;

USE auth_server;

-- -----------------------------------------------------------
-- OAuth 2.0 客户端注册表
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS oauth_clients (
    id                BIGINT PRIMARY KEY AUTO_INCREMENT,
    client_id         VARCHAR(64)  NOT NULL UNIQUE,
    client_secret_hash VARCHAR(256) NOT NULL COMMENT 'bcrypt hash of client_secret',
    client_name       VARCHAR(128) NOT NULL DEFAULT '',
    redirect_uris     TEXT         NOT NULL COMMENT 'JSON array, e.g. ["https://a.com/cb"]',
    grant_types       VARCHAR(128) NOT NULL DEFAULT 'authorization_code',
    allowed_scopes    VARCHAR(256) NOT NULL DEFAULT 'openid profile',
    client_uri        VARCHAR(512) NOT NULL DEFAULT '',
    logo_uri          VARCHAR(512) NOT NULL DEFAULT '',
    enabled           TINYINT(1)   NOT NULL DEFAULT 1,
    created_at        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- -----------------------------------------------------------
-- 用户表
-- -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS oauth_users (
    id                BIGINT PRIMARY KEY AUTO_INCREMENT,
    username          VARCHAR(64)  NOT NULL UNIQUE,
    email             VARCHAR(128) NOT NULL UNIQUE,
    password_hash     VARCHAR(256) NOT NULL COMMENT 'bcrypt hash',
    display_name      VARCHAR(128) NOT NULL DEFAULT '',
    avatar_url        VARCHAR(512) NOT NULL DEFAULT '',
    email_verified    TINYINT(1)   NOT NULL DEFAULT 0,
    enabled           TINYINT(1)   NOT NULL DEFAULT 1,
    created_at        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
