# 业务服务接入 OIDC 认证指南

## 概述

本认证服务（AuthServer）实现标准的 **OpenID Connect (OIDC)** 协议，业务服务通过 OAuth 2.0 授权码流程获取用户身份信息。

**核心原则：认证与业务数据分离**
- AuthServer 只负责身份认证（你是谁、能不能登录）
- 业务服务拿到 `sub`（用户 ID）后，查自己的数据库获取业务数据

## 接入流程

### 1. 注册客户端

在 `oauth_clients` 表注册业务服务：

```sql
INSERT INTO oauth_clients (
    client_id,       -- 客户端 ID（唯一标识）
    client_secret_hash,  -- client_secret 的 bcrypt 哈希
    client_name,     -- 客户端名称
    redirect_uris,   -- 回调 URI 白名单（JSON 数组）
    grant_types,     -- 允许的 grant_type
    allowed_scopes   -- 允许的 scope
)
VALUES (
    'my_service',
    '<bcrypt_hash>',          -- tools/gen_hash 生成
    '我的业务服务',
    '["https://my-service.com/callback"]',  -- 回调地址
    'authorization_code,refresh_token',
    'openid profile email'
);
```

生成 client_secret 哈希：

```bash
LD_LIBRARY_PATH=chen-sdk-1.3.1/lib:/usr/local/lib tools/gen_hash "my_secret"
```

### 2. 配置 NGINX（网关层）

NGINX 作为统一入口，将认证请求转发到 AuthServer，业务请求转发到业务服务。

```nginx
# 认证服务
upstream auth_server {
    server 127.0.0.1:8090;
}

# 业务服务示例
upstream biz_service {
    server 127.0.0.1:9000;
}

server {
    listen 443 ssl;
    server_name api.example.com;

    # ─── 认证相关路径 → AuthServer ───
    location ~ ^/(\.well-known|jwks\.json|authorize|login|token|userinfo) {
        proxy_pass http://auth_server;
    }

    # ─── 业务路径 → 业务服务 ───
    location /api/ {
        # 可选：在网关层校验 token
        auth_request /auth/validate;

        proxy_set_header X-User-Id $sent_http_x_user_id;
        proxy_pass http://biz_service;
    }

    # Token 校验（用子请求方式）
    location = /auth/validate {
        internal;
        proxy_method GET;
        proxy_pass http://auth_server/userinfo;
        proxy_set_header Authorization $http_authorization;

        # token 有效 → 继续业务请求
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
    }
}
```

### 3. OIDC 发现端点

获取认证服务的元数据：

```bash
curl https://api.example.com/.well-known/openid-configuration
```

返回示例：

```json
{
  "code": "200",
  "message": "ok",
  "data": {
    "issuer": "https://api.example.com",
    "authorization_endpoint": "https://api.example.com/authorize",
    "token_endpoint": "https://api.example.com/token",
    "userinfo_endpoint": "https://api.example.com/userinfo",
    "jwks_uri": "https://api.example.com/jwks.json",
    "scopes_supported": ["openid", "profile", "email"],
    "response_types_supported": ["code"],
    "grant_types_supported": ["authorization_code", "refresh_token"],
    "id_token_signing_alg_values_supported": ["RS256"],
    "subject_types_supported": ["public"]
  }
}
```

### 4. 公钥获取

Token 验签用的 RSA 公钥：

```bash
curl https://api.example.com/jwks.json
```

```json
{
  "code": "200",
  "message": "ok",
  "data": {
    "keys": [{
      "kty": "RSA",
      "kid": "rsa1",
      "alg": "RS256",
      "use": "sig",
      "n": "0vx7ago...",
      "e": "AQAB"
    }]
  }
}
```

### 5. 授权码流程（完整时序）

#### 5.1 浏览器场景（Web 应用）

```
用户访问业务服务 → 未登录 → 重定向到 AuthServer

  302 GET https://api.example.com/authorize
    ?response_type=code
    &client_id=my_service
    &redirect_uri=https://my-service.com/callback
    &scope=openid%20profile%20email
    &state=random_state_string

用户登录 → AuthServer 派发授权码

  302 https://my-service.com/callback
    ?code=xxxxx
    &state=random_state_string

业务服务后端用 code 换 token

  POST https://api.example.com/token
    Content-Type: application/x-www-form-urlencoded

    grant_type=authorization_code
    &code=xxxxx
    &redirect_uri=https://my-service.com/callback
    &client_id=my_service
    &client_secret=my_secret

返回：

  {
    "code": "200",
    "data": {
      "access_token": "eyJhbG...",
      "id_token": "eyJhbG...",
      "refresh_token": "xxxxx",
      "token_type": "Bearer",
      "expires_in": 3600
    }
  }
```

#### 5.2 后端服务场景（服务间调用）

如 Python 示例：

```python
import base64, requests

# Step 1: 用户已登录，拿到授权码 code
code = "xxxxx"

# Step 2: 换 token
r = requests.post("https://api.example.com/token", data={
    "grant_type": "authorization_code",
    "code": code,
    "redirect_uri": "https://my-service.com/callback",
    "client_id": "my_service",
    "client_secret": "my_secret",
})
token_data = r.json()["data"]
access_token = token_data["access_token"]
refresh_token = token_data["refresh_token"]

# Step 3: 获取用户信息
r = requests.get("https://api.example.com/userinfo",
    headers={"Authorization": f"Bearer {access_token}"})
user = r.json()["data"]
sub = user["sub"]  # 用户唯一 ID，关联业务数据的 key

# Step 4: 用 sub 查业务数据
biz_user = my_db.query("SELECT * FROM biz_users WHERE sub = ?", sub)
```

## Token 结构

### Access Token（用于调用 API）

```json
// JWT Header
{"alg":"RS256","kid":"rsa1","typ":"JWT"}

// JWT Payload
{
  "iss": "https://api.example.com",
  "sub": "10001",              // 用户 ID（只读不解释）
  "aud": "my_service",          // 目标客户端
  "client_id": "my_service",
  "exp": 1735689600,            // 过期时间戳
  "iat": 1735686000,            // 签发时间戳
  "scope": "openid profile email"
}

// 签名验证用 JWTK 公钥
```

### ID Token（用户身份声明）

```json
{
  "iss": "https://api.example.com",
  "sub": "10001",
  "aud": "my_service",
  "exp": 1735689600,
  "iat": 1735686000,
  "auth_time": 1735686000,
  "nonce": "xxx",
  "name": "张三",
  "preferred_username": "zhangsan",
  "email": "zhangsan@example.com",
  "email_verified": true
}
```

### Refresh Token（用于续期）

- 随机字符串（非 JWT），存储在 Redis
- 使用轮换机制：每次 refresh 发放新 RT，旧 RT 失效
- 过期时间：默认 30 天

## Token 验证

### 方式一：本地验签（推荐，无状态）

业务服务可以直接用 RS256 公钥验证 access_token，无需调用 AuthServer。

```python
import jwt
import requests

# 获取公钥
jwks = requests.get("https://api.example.com/jwks.json").json()
jwks_data = jwks.get("data", jwks)

# 解析 headers 获取 kid
headers = jwt.get_unverified_header(access_token)
key = next(k for k in jwks_data["keys"] if k["kid"] == headers["kid"])

# 验签
payload = jwt.decode(
    access_token,
    key,
    algorithms=["RS256"],
    audience="my_service",
    issuer="https://api.example.com",
)

sub = payload["sub"]  # 用户 ID
scope = payload.get("scope", "").split(" ")  # 权限范围
```

### 方式二：网关子请求校验（推荐，集中管控）

NGINX 配置 `auth_request` 指向 `/userinfo`，校验通过后传递 `X-User-Id` 头。

### 方式三：自建验签

```cpp
#include <JwtUtil.hpp>

Json::Value payload;
if (JwtUtil::verifyJWT(access_token, publicKeyPem, payload)) {
    std::string sub = payload["sub"].asString();
    // sub = "10001"
}
```

## UserInfo 端点

```
GET /userinfo
Authorization: Bearer <access_token>
```

返回示例：

```json
{
  "code": "200",
  "message": "ok",
  "data": {
    "sub": "10001",              // 用户唯一 ID
    "name": "张三",               // profile scope
    "preferred_username": "zhangsan",  // profile scope
    "email": "zhangsan@example.com",   // email scope
    "email_verified": true             // email scope
  }
}
```

`sub` 字段是连接认证与业务数据的关联键。业务服务用 `sub` 查自己的数据库获取业务特有的用户信息。

**注意**：scope 控制返回哪些字段：
- `openid` — 必须，返回 `sub`（用户 ID）
- `profile` — 返回 `name`、`preferred_username`
- `email` — 返回 `email`、`email_verified`

## Token 刷新

### 请求

```bash
curl -X POST https://api.example.com/token \
  -d "grant_type=refresh_token" \
  -d "refresh_token=xxxxx" \
  -d "client_id=my_service" \
  -d "client_secret=my_secret"
```

### 响应

```json
{
  "code": "200",
  "data": {
    "access_token": "eyJhbG...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "yyyyy"    // 新 RT，旧 RT 已失效
  }
}
```

## 安全说明

1. **client_secret** — 不要泄露给前端，仅在后端使用
2. **授权码** — 一次性使用，5 分钟过期
3. **Access Token** — 1 小时过期，JWT 无状态无法主动撤销
4. **Refresh Token** — 30 天过期，支持轮换（旧 RT 刷新后立即失效）
5. **redirect_uri** — 必须在白名单内，防止开放重定向
6. **state 参数** — 防止 CSRF 攻击，必须校验
7. **HTTPS** — 生产环境必须开启

## 响应格式

所有接口使用统一响应封装：

```json
{
  "code": "200",         // 业务状态码
  "message": "ok",       // 状态描述
  "used": 0.123,         // 处理耗时（秒）
  "data": { ... }        // 业务数据
}
```

常见错误码：

| code | 说明 |
|------|------|
| 200 | 成功 |
| 400 | 参数错误（如 invalid_request、invalid_grant） |
| 401 | 未授权（如 invalid_token、invalid_client） |
| 404 | 资源不存在 |
| 500 | 服务端错误 |

## 测试验证

```bash
# 1. 获取有效 access_token（通过完整授权码流程）
python3 tests/test_oidc_flow.py

# 2. 直接验证单个 token
curl https://api.example.com/userinfo \
  -H "Authorization: Bearer <access_token>"

# 3. 验证过期 token 应返回 401
# 4. 验证错误 scope 应返回有限字段
# 5. 刷新 token 应返回新 token，旧 token 失效
```
