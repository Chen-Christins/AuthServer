# AuthServer API 参考

## 基础信息

| 项目 | 说明 |
|------|------|
| 协议 | OAuth 2.1 + OpenID Connect |
| 签名算法 | RS256 |
| 响应格式 | `{code, message, used, data}` |
| Token 类型 | Bearer |

## 端点一览

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/.well-known/openid-configuration` | OIDC 发现元数据 |
| GET | `/jwks.json` | RSA 公钥 JWK Set |
| GET | `/authorize` | 授权码请求（浏览器重定向） |
| GET/POST | `/login` | 登录页面 / 表单提交 |
| POST | `/token` | 令牌交换 / 刷新 |
| GET | `/userinfo` | 用户信息 |

---

## OIDC 发现

```
GET /.well-known/openid-configuration
```

返回认证服务的元数据，包括所有端点地址、支持的 scope/grant_type/算法等。

---

## JWKS

```
GET /jwks.json
```

返回 RSA 公钥列表，用于客户端本地验签 access_token / id_token。

---

## 授权码请求

```
GET /authorize?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}&state={state}
```

**参数**

| 参数 | 必填 | 说明 |
|------|------|------|
| `response_type` | 是 | 固定 `code` |
| `client_id` | 是 | 客户端 ID |
| `redirect_uri` | 是 | 回调地址，必须在客户端白名单内 |
| `scope` | 是 | 必须包含 `openid`，可选 `profile` `email` |
| `state` | 推荐 | CSRF 防伪造，回调时会原样返回 |
| `nonce` | 否 | 关联 id_token，防重放 |

**流程**

1. 未登录 → 302 重定向到 `/login`，登录后回到此端点
2. 已登录 → 302 重定向到 `redirect_uri?code={code}&state={state}`
3. 参数错误 → 返回 400 或重定向到 `redirect_uri?error={error}`

---

## 登录

```
GET /login?redirect={redirect_uri}
```

渲染登录表单页面。

```
POST /login
Content-Type: application/x-www-form-urlencoded

username={username}&password={password}&redirect={redirect_uri}
```

**参数**

| 参数 | 必填 | 说明 |
|------|------|------|
| `username` | 是 | 用户名 |
| `password` | 是 | 密码 |
| `redirect` | 是 | 登录成功后重定向地址 |

登录成功 → 302 重定向到 `redirect`，同时设置 `SESSIONID` cookie。  
登录失败 → 302 重定向到 `/login?error=1&redirect=...`

---

## 令牌交换

```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code={code}
&redirect_uri={redirect_uri}
&client_id={client_id}
&client_secret={client_secret}
```

**参数**

| 参数 | 必填 | 说明 |
|------|------|------|
| `grant_type` | 是 | `authorization_code` 或 `refresh_token` |
| `code` | authorization_code 时必填 | 授权码 |
| `refresh_token` | refresh_token 时必填 | 刷新令牌 |
| `redirect_uri` | authorization_code 时必填 | 必须与授权请求一致 |
| `client_id` | 是 | 客户端 ID |
| `client_secret` | 是 | 客户端密钥 |

**响应**

```json
{
  "code": "200",
  "data": {
    "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6InJzYTEiLCJ0eXAiOiJKV1QifQ...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6InJzYTEiLCJ0eXAiOiJKV1QifQ...",
    "refresh_token": "c4e34417d47fd985..."
  }
}
```

**access_token 字段**

| 字段 | 说明 |
|------|------|
| `iss` | 签发者 URL |
| `sub` | 用户 ID（业务服务关联键） |
| `aud` | 目标客户端 ID |
| `scope` | 授权范围 |
| `exp` | 过期时间（Unix 秒） |
| `iat` | 签发时间（Unix 秒） |

**id_token 字段**

标准 OIDC ID Token，RS256 签名。包含 `sub`、`iss`、`aud`、`exp`、`iat` 等标准 claims，以及根据 scope 返回的 `name`、`preferred_username`、`email`。

---

## 令牌刷新

```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token={refresh_token}
&client_id={client_id}
&client_secret={client_secret}
```

**响应**

```json
{
  "code": "200",
  "data": {
    "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6InJzYTEiLCJ0eXAiOiJKV1QifQ...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "new_refresh_token_here"
  }
}
```

注意：refresh_token 使用轮换机制，每次刷新后旧 token 立即失效。

---

## 用户信息

```
GET /userinfo
Authorization: Bearer {access_token}
```

**响应**

```json
{
  "code": "200",
  "data": {
    "sub": "10001",
    "name": "张三",
    "preferred_username": "zhangsan",
    "email": "zhangsan@example.com",
    "email_verified": true
  }
}
```

返回字段由请求时的 `scope` 决定：

| scope | 返回字段 |
|-------|----------|
| `openid` | `sub` |
| `profile` | `name`、`preferred_username` |
| `email` | `email`、`email_verified` |

`sub` 是用户唯一标识，业务服务用它关联自己的业务数据。

---

## 错误码

| HTTP 状态码 | code | 说明 |
|-------------|------|------|
| 400 | `invalid_request` | 缺少必填参数 |
| 400 | `invalid_scope` | scope 不合法 |
| 400 | `invalid_grant` | 授权码或 refresh_token 无效/已过期 |
| 400 | `unsupported_grant_type` | 不支持的 grant_type |
| 400 | `unsupported_response_type` | 不支持的 response_type |
| 401 | `invalid_client` | client_id 或 client_secret 错误 |
| 401 | `invalid_token` | access_token 无效或已过期 |
| 404 | `user_not_found` | 用户不存在 |
| 500 | `server_error` | 服务端内部错误 |

---

## 数据模型

### oauth_clients

| 字段 | 类型 | 说明 |
|------|------|------|
| `client_id` | varchar(64) | 客户端 ID |
| `client_secret_hash` | varchar(256) | client_secret 的 bcrypt 哈希 |
| `client_name` | varchar(128) | 客户端名称 |
| `redirect_uris` | text | 回调 URI 白名单（JSON 数组） |
| `grant_types` | varchar(128) | 允许的 grant_type |
| `allowed_scopes` | varchar(256) | 允许的 scope |
| `enabled` | int | 是否启用 |

### oauth_users

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | bigint | 用户 ID（即 sub） |
| `username` | varchar(64) | 用户名 |
| `email` | varchar(128) | 邮箱 |
| `password_hash` | varchar(256) | bcrypt 密码哈希 |
| `display_name` | varchar(128) | 显示名称 |
| `enabled` | int | 是否启用 |

---

## 安全要求

- `client_secret` 仅在后端使用，不暴露给前端
- `redirect_uri` 必须与注册时一致
- `state` 参数防止 CSRF
- 授权码一次性使用，5 分钟过期
- Refresh Token 每次刷新后轮换
- 生产环境必须使用 HTTPS
