# OIDC 授权码流程测试

## 前置条件

```bash
pip install -r tests/requirements.txt
```

## 运行

```bash
# 确保 AuthServer 已启动
bin/server -s

# 执行测试
python3 tests/test_oidc_flow.py
```

## 测试内容

| Step | 端点 | 验证点 |
|------|------|--------|
| 0 | — | 服务存活检查 + 种子数据写入 MySQL |
| 1 | `/.well-known/openid-configuration` | OIDC 元数据 |
| 2 | `/jwks.json` | RSA 公钥 JWK Set |
| 3 | `/authorize` → `/login` → redirect | 授权码获取（含登录会话） |
| 4 | `/token` | code → access_token + id_token + refresh_token |
| 5 | `/userinfo` | access_token → 用户 claims（sub/name/email） |
| 6 | `/token` (refresh_token) | Refresh Token 轮换 |
| 7 | `/token` (旧 refresh_token) | 旧 token 被拒绝 |

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `AUTH_HOST` | `localhost:8090` | AuthServer 地址 |
| `DB_HOST` | `192.168.139.3` | MySQL 主机 |
| `DB_PASS` | `123456` | MySQL 密码 |
