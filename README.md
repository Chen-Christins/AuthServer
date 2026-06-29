# AuthServer — OIDC 认证服务

基于 chen-sdk 框架的 OpenID Connect 认证服务，提供标准的 OAuth 2.1 + OIDC 授权码流程。

## 架构

```
NGINX (网关, proxy_pass → :8090)
  │
  ▼
chen HTTP Server (:8090)
  │
  ├── JWT RS256 签名（无状态 access_token）
  ├── MySQL — oauth_users + oauth_clients
  └── Redis — 授权码(5min) + 会话(24h) + refresh_token(30d)
```

### 目录结构

```
├── bin/
│   ├── conf/system.yml       ← 服务配置
│   ├── conf/keys/            ← RSA 密钥对（setup.sh 生成）
│   └── module/libauth.so     ← 编译产物
├── chen-sdk-1.3.1/           ← 框架 SDK
├── cmake/                    ← CMake 模块
├── dbproxy/
│   ├── xml/                  ← ORM 表定义（XML）
│   └── data/                 ← ORM 生成代码
├── src/
│   ├── AuthModule.cc         ← 模块入口 + 路由注册
│   ├── JwtUtil.cc            ← JWT 创建/验签 + JWK 导出
│   ├── OidcConfig.cc         ← 配置加载
│   ├── Store.cc              ← 数据层（User/Client/Code/Session/Token）
│   ├── util.h                ← DB/Redis 连接辅助
│   └── servlets/
│       ├── OidcDiscoveryServlet  → /.well-known/openid-configuration
│       ├── JwksServlet           → /jwks.json
│       ├── AuthorizationServlet  → /authorize
│       ├── LoginServlet          → /login
│       ├── TokenServlet          → /token
│       └── UserInfoServlet       → /userinfo
├── tests/
│   ├── test_oidc_flow.py     ← 自动化测试
│   ├── requirements.txt
│   └── README.md
└── tools/
    ├── setup.sh              ← 初始化（生成密钥 + 种子数据）
    └── gen_hash.cc           ← bcrypt 哈希生成工具
```

## 快速启动

### 1. 依赖

- MySQL 8.0+
- Redis 6+
- OpenSSL 3.x

### 2. 初始化

```bash
# 生成 RSA 密钥对 + 种子数据 SQL
./tools/setup.sh

# 执行输出的 SQL 插入测试数据
mysql -h 192.168.139.3 -u root -p auth
```

### 3. 配置

编辑 `bin/conf/system.yml`，确认以下配置：

```yaml
mysql:
  dbs:
    auth:
      host: 192.168.139.3
      port: 3306
      user: root
      passwd: 123456
      dbname: auth

redis:
  config:
    auth:
      host: 127.0.0.1:6379
      type: fox_redis
      pool: 2

auth:
  issuer: "http://localhost:8090"
  key:
    kid: "rsa1"
    private_key_path: "bin/conf/keys/private.pem"
    public_key_path: "bin/conf/keys/public.pem"
```

### 4. 编译 & 启动

```bash
# 编译
cd build && cmake .. && make -j4 auth

# 启动
cd .. && bin/server -s
```

### 5. 测试

```bash
pip install -r tests/requirements.txt
python3 tests/test_oidc_flow.py
```

## API 端点

| 路径 | 方法 | 说明 |
|------|------|------|
| `/.well-known/openid-configuration` | GET | OIDC 发现元数据 |
| `/jwks.json` | GET | RSA 公钥 JWK Set |
| `/authorize` | GET | 授权码请求（浏览器重定向） |
| `/login` | GET/POST | 登录页面 / 表单提交 |
| `/token` | POST | 令牌交换 / 刷新 |
| `/userinfo` | GET | 用户信息（Bearer Token） |

### 授权码流程

```
浏览器 → GET /authorize?response_type=code&client_id=xxx&...
       → 302 /login
       → POST /login (username+password)
       → 302 /authorize (with SESSIONID cookie)
       → 302 redirect_uri?code=xxx&state=yyy

客户端 → POST /token (grant_type=authorization_code + code)
       → { access_token, id_token, refresh_token, token_type, expires_in }

客户端 → GET /userinfo (Authorization: Bearer access_token)
       → { sub, name, preferred_username, email }
```

### Token 结构

**ID Token** (JWT RS256 签名):
```json
{"iss":"http://localhost:8090","sub":"1","aud":"test_client","exp":...,"iat":...}
```

**Access Token** (JWT RS256 签名):
```json
{"iss":"http://localhost:8090","sub":"1","aud":"test_client","scope":"openid profile email","exp":...,"iat":...}
```

## 支持的 grant_type

| grant_type | 说明 |
|------------|------|
| `authorization_code` | 授权码（推荐，OAuth 2.1 唯一推荐） |
| `refresh_token` | 刷新令牌（含轮换） |

已废弃（OAuth 2.1）：implicit、password、client_credentials

## 响应格式

所有 JSON 响应使用 `Result` 封装：

```json
{"code":"200","message":"ok","used":0.123,"data":{...}}
```

- `code` — 业务状态码（字符串）
- `message` — 状态描述
- `used` — 处理耗时（秒）
- `data` — 响应数据
