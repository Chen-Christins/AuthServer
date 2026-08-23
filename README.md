# AuthServer — OIDC 认证服务

基于 chen-sdk 框架的 OpenID Connect 认证服务，提供标准的 OAuth 2.1 + OIDC 授权码流程。

## 架构

```
chen HTTP Server (:8090)
  │
  ├── JWT RS256 签名（无状态 access_token / id_token）
  ├── MySQL — oauth_users + oauth_clients
  └── Redis — 授权码(5min) + 会话(24h) + refresh_token(30d)
```

### 目录结构

```
├── bin/
│   ├── server                ← 服务主程序（chen-sdk 运行时）
│   ├── conf/
│   │   ├── system.yml        ← 服务/日志/MySQL/Redis 配置
│   │   └── auth.yml          ← OIDC 配置（issuer/key/token）
│   ├── keys/
│   │   ├── private.pem       ← RSA 私钥（测试密钥，已入库）
│   │   └── public.pem        ← RSA 公钥（测试密钥，已入库）
│   └── module/libauth.so     ← 编译产物（AuthModule）
├── chen-sdk-1.3.1/           ← 框架 SDK
├── cmake/                    ← CMake 模块
├── dbproxy/
│   ├── xml/                  ← ORM 表定义（XML）
│   └── data/                 ← ORM 生成代码
├── docs/                     ← 接口文档
├── src/
│   ├── AuthModule.cc         ← 模块入口 + 路由注册
│   ├── JwtUtil.cc            ← JWT 创建/验签 + JWK 导出
│   ├── OidcConfig.hpp        ← OIDC 配置结构（AuthConf + LexicalCast）
│   ├── Store.cc              ← 数据层（User/Client/Code/Session/Token）
│   ├── Struct.cc             ← Result 响应封装 + AuthServlet 基类
│   ├── util.h                ← DB/Redis 连接辅助
│   └── servlets/
│       ├── OidcDiscoveryServlet  → /.well-known/openid-configuration
│       ├── JwksServlet           → /jwks.json
│       ├── AuthorizationServlet  → /authorize
│       ├── LoginServlet          → /login
│       ├── TokenServlet          → /token
│       └── UserInfoServlet       → /userinfo
└── tests/
    ├── test_oidc_flow.py     ← 端到端自动化测试（含种子数据写入）
    ├── requirements.txt
    └── README.md
```

## 快速启动

### 1. 依赖

- MySQL 8.0+
- Redis 6+
- OpenSSL 3.x

### 2. 配置

OIDC 配置在 `bin/conf/auth.yml`：

```yaml
auth:
  issuer: "http://localhost:8090"
  key:
    kid: rsa1
    private_key_path: /home/chen/workspace/AuthServer/bin/keys/private.pem
    public_key_path: /home/chen/workspace/AuthServer/bin/keys/public.pem
  token:
    access_token_ttl: 3600       # 1h — JWT 无状态
    id_token_ttl: 3600           # 1h — ID Token 也是 JWT
    refresh_token_ttl: 2592000   # 30d — Redis 自动过期
    auth_code_ttl: 300           # 5min — Redis 自动过期
  session_ttl: 86400             # 24h — Redis 自动过期
```

MySQL / Redis 连接在 `bin/conf/system.yml` 的 `mysql.dbs.auth` 与 `redis.config.auth` 中配置。

> RSA 密钥已随仓库提供（测试密钥），生产环境请替换为自签名密钥。

### 3. 编译 & 启动

```bash
cd build && cmake .. && make -j4 auth

# 启动
cd .. && bin/server -s
```

### 4. 测试

```bash
pip install -r tests/requirements.txt
python3 tests/test_oidc_flow.py   # 会自动写入测试种子数据
```

## API 端点

| 路径 | 方法 | 说明 |
|------|------|------|
| `/.well-known/openid-configuration` | GET | OIDC 发现元数据 |
| `/jwks.json` | GET | RSA 公钥 JWK Set |
| `/authorize` | GET | 授权码请求（未登录返回 401） |
| `/login` | POST | 登录（JSON 表单） |
| `/token` | POST | 令牌交换 / 刷新 |
| `/userinfo` | GET | 用户信息（Bearer Token） |

### 授权码流程

```
客户端 → GET /authorize?response_type=code&client_id=xxx&...
       → 无会话 → 401 login_required（前端自行引导登录）

客户端 → POST /login {"username","password"}
       → 200 + Set-Cookie: SESSIONID=xxx

客户端 → GET /authorize（携带 SESSIONID cookie）
       → 302 redirect_uri?code=xxx&state=yyy

客户端 → POST /token (grant_type=authorization_code + code)
       → { access_token, id_token, refresh_token, token_type, expires_in }

客户端 → GET /userinfo (Authorization: Bearer access_token)
       → { sub, name, preferred_username, email }
```

### Token 结构

**ID Token**（JWT RS256 签名）:
```json
{"iss":"http://localhost:8090","sub":"1","aud":"test_client","exp":...,"iat":...,"auth_time":...}
```

**Access Token**（JWT RS256 签名）:
```json
{"iss":"http://localhost:8090","sub":"1","aud":"test_client","client_id":"test_client","scope":"openid profile email","exp":...,"iat":...}
```

## 支持的 grant_type

| grant_type | 说明 |
|------------|------|
| `authorization_code` | 授权码（OAuth 2.1 推荐） |
| `refresh_token` | 刷新令牌（含轮换） |

已废弃（OAuth 2.1）：implicit、password、client_credentials

## 响应格式

所有 JSON 响应使用 `Result` 封装：

```json
{"code":"200","message":"ok","used":0.123,"data":{...}}
```

- `code` — 业务状态码（字符串）
- `message` — 状态描述
- `used` — 处理耗时（毫秒）
- `data` — 响应数据（无数据时省略）

## 配置说明

OIDC 配置通过 `ConfigVar<AuthConf>` 加载，配置项定义见 `src/OidcConfig.hpp`（`AuthConf` / `KeyConf` / `TokenConf`），由各 servlet 通过 `chen::Config::Lookup("auth", AuthConf(), ...)` 读取。
