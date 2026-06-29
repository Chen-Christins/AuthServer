#!/usr/bin/env python3
"""
OIDC 授权码流程完整测试脚本
测试前确保服务已启动，MySQL 和 Redis 可用。

用法:
    python3 tests/test_oidc_flow.py

环境变量覆盖默认值:
    AUTH_HOST   (默认 localhost:8090)
    DB_HOST     (默认 192.168.139.3)
    DB_PASS     (默认 123456)
"""
import base64
import json
import os
import sys
import urllib.parse

import requests

# ============================================================
# 配置
# ============================================================
AUTH_BASE = f"http://{os.getenv('AUTH_HOST', 'localhost:8090')}"
DB_HOST = os.getenv("DB_HOST", "192.168.139.3")
DB_PASS = os.getenv("DB_PASS", "123456")

CLIENT_ID = "test_client"
CLIENT_SECRET = "test_secret"
USERNAME = "testuser"
PASSWORD = "test123"

OK = "  ✅"
FAIL = "  ❌"
SKIP = "  ⏭"

session = requests.Session()


# ============================================================
# 工具函数
# ============================================================
def expect(resp, code=200, msg=None):
    """检查 Result 响应"""
    if resp.status_code != code:
        print(f"{FAIL} HTTP {resp.status_code}, 期望 {code}")
        print(f"     body: {resp.text[:300]}")
        return False
    try:
        data = resp.json()
    except json.JSONDecodeError:
        print(f"{FAIL} 响应不是合法 JSON: {resp.text[:200]}")
        return False
    if msg and data.get("message") != msg:
        print(f"{FAIL} message={data.get('message')}, 期望={msg}")
        print(f"     body: {resp.text[:200]}")
        return False
    return data


# ============================================================
# Step 0 — 前置检查与种子数据
# ============================================================
print("=" * 60)
print("OIDC 授权码流程测试")
print("=" * 60)
print(f"  Auth Server: {AUTH_BASE}")
print(f"  MySQL:       {DB_HOST}:3306")
print(f"  Client:      {CLIENT_ID}")
print(f"  User:        {USERNAME}")
print()

try:
    r = requests.get(f"{AUTH_BASE}/.well-known/openid-configuration",
                     timeout=3)
    r.raise_for_status()
    print(f"{OK} AuthServer 已启动")
except requests.ConnectionError:
    print(f"{FAIL} AuthServer 未启动 ({AUTH_BASE})")
    print(f"    请先启动: ./bin/main -d -c bin/conf/system.yml")
    sys.exit(1)

# 用 Python bcrypt 生成哈希并写入 MySQL
try:
    import bcrypt
    import pymysql

    cs_hash = bcrypt.hashpw(CLIENT_SECRET.encode(), bcrypt.gensalt()).decode()
    pw_hash = bcrypt.hashpw(PASSWORD.encode(), bcrypt.gensalt()).decode()
    print(f"{OK} bcrypt hashes generated (Python bcrypt)")
    print(f"     client_secret hash: {cs_hash[:20]}...")
    print(f"     password hash:      {pw_hash[:20]}...")

    conn = pymysql.connect(
        host=DB_HOST, port=3306, user="root",
        passwd=DB_PASS, db="auth", charset="utf8mb4")
    cur = conn.cursor()

    # 删除旧数据后重新插入，确保数据干净
    cur.execute("DELETE FROM oauth_clients WHERE client_id = %s",
                (CLIENT_ID,))
    cur.execute("DELETE FROM oauth_users WHERE username = %s",
                (USERNAME,))

    cur.execute("""
        INSERT INTO oauth_clients
            (client_id, client_secret_hash, client_name,
             redirect_uris, grant_types, allowed_scopes)
        VALUES (%s, %s, 'Test Client',
                '["http://localhost:3000/callback"]',
                'authorization_code,refresh_token',
                'openid profile email')
    """, (CLIENT_ID, cs_hash))

    cur.execute("""
        INSERT INTO oauth_users
            (username, email, password_hash, display_name)
        VALUES (%s, %s, %s, 'Test User')
    """, (USERNAME, f"{USERNAME}@example.com", pw_hash))

    conn.commit()

    # 回读验证
    cur.execute("SELECT password_hash FROM oauth_users WHERE username=%s",
                (USERNAME,))
    stored_pw = cur.fetchone()[0]
    cur.execute("SELECT client_secret_hash FROM oauth_clients "
                 "WHERE client_id=%s", (CLIENT_ID,))
    stored_cs = cur.fetchone()[0]
    if stored_pw == pw_hash and stored_cs == cs_hash:
        print(f"{OK} 种子数据写入 MySQL 并回读验证通过")
    else:
        print(f"{FAIL} 回读的 hash 不一致!")
        print(f"     password_hash: 写入={pw_hash}, 回读={stored_pw}")
        print(f"     client_secret: 写入={cs_hash}, 回读={stored_cs}")

    cur.close()
    conn.close()

except ImportError:
    print(f"{SKIP} 未安装 pymysql，跳过种子数据写入")
    print(f"     请先执行 tools/setup.sh 插入数据")
except Exception as e:
    print(f"{FAIL} 种子数据写入失败: {e}")
    sys.exit(1)

print()


# ============================================================
# Step 1 — Discovery
# ============================================================
print("--- Step 1: OIDC Discovery ---")
r = requests.get(f"{AUTH_BASE}/.well-known/openid-configuration")
d = expect(r, 200, "ok")
if d:
    data = d.get("data", d)
    print(f"{OK} issuer:          {data.get('issuer')}")
    print(f"{OK} authorize:       {data.get('authorization_endpoint')}")
    print(f"{OK} token:           {data.get('token_endpoint')}")
    print(f"{OK} userinfo:        {data.get('userinfo_endpoint')}")
    print(f"{OK} jwks_uri:        {data.get('jwks_uri')}")
print()


# ============================================================
# Step 2 — JWKS
# ============================================================
print("--- Step 2: JWKS ---")
r = requests.get(f"{AUTH_BASE}/jwks.json", headers={"Connection": "close"})
d = expect(r, 200, "ok")
if d:
    keys = d.get("data", d).get("keys", [])
    if keys:
        print(f"{OK} JWK keys count: {len(keys)}")
        print(f"     kid: {keys[0].get('kid')}, kty: {keys[0].get('kty')}")
    else:
        print(f"{FAIL} JWKS 无 keys")
print()


# ============================================================
# Step 3 — 授权码流程
# ============================================================
print("--- Step 3: 授权码流程 ---")

# 3a. 发起 /authorize（未登录应返回 login_required）
authz_params = {
    "response_type": "code",
    "client_id": CLIENT_ID,
    "redirect_uri": "http://localhost:3000/callback",
    "scope": "openid profile email",
    "state": "test_state_123",
}
r = session.get(f"{AUTH_BASE}/authorize",
                params=authz_params, allow_redirects=False)
if r.status_code != 401:
    print(f"{FAIL} /authorize 期望 401, 收到 {r.status_code}")
    if r.text:
        print(f"     body: {r.text[:200]}")
    sys.exit(1)

data = expect(r, 401, "login_required")
if not data:
    sys.exit(1)
print(f"{OK} 未登录 → 401 login_required")

# 3b. 登录（POST /login, JSON body）
r = session.post(f"{AUTH_BASE}/login",
    json={"username": USERNAME, "password": PASSWORD})
d = expect(r, 200, "ok")
if not d:
    print(f"{FAIL} 登录失败")
    try:
        import pymysql
        conn = pymysql.connect(host=DB_HOST, port=3306, user="root",
                                passwd=DB_PASS, db="auth", charset="utf8mb4")
        cur = conn.cursor()
        cur.execute("SELECT username, password_hash FROM oauth_users "
                     "WHERE username=%s", (USERNAME,))
        row = cur.fetchone()
        if row:
            print(f"     MySQL 中有用户 {row[0]}, hash={row[1]}")
        else:
            print(f"     用户 {USERNAME} 在 MySQL 中不存在!")
    except Exception as e2:
        print(f"     MySQL 查询也失败了: {e2}")
    sys.exit(1)

print(f"{OK} 登录成功")

# 3c. 再次请求 /authorize（带上 session cookie）
r = session.get(f"{AUTH_BASE}/authorize",
                params=authz_params, allow_redirects=False)
if r.status_code != 302:
    print(f"{FAIL} /authorize (已登录) 期望 302, 收到 {r.status_code}")
    print(f"     body: {r.text[:200]}")
    sys.exit(1)

# 提取授权码
callback_url = r.headers.get("Location", "")
parsed = urllib.parse.urlparse(callback_url)
cb_params = urllib.parse.parse_qs(parsed.query)
auth_code = cb_params.get("code", [None])[0]
cb_state = cb_params.get("state", [None])[0]
if not auth_code:
    print(f"{FAIL} 未收到授权码, Location={callback_url}")
    sys.exit(1)
if cb_state != "test_state_123":
    print(f"{FAIL} state 不匹配: {cb_state}")
    sys.exit(1)
print(f"{OK} 授权码获取成功")
print(f"     code:   {auth_code[:16]}...")
print(f"     state:  {cb_state}")
print()


# ============================================================
# Step 4 — Token 交换
# ============================================================
print("--- Step 4: Token 交换 ---")

basic_auth = base64.b64encode(
    f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()

r = requests.post(f"{AUTH_BASE}/token",
    data={
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": "http://localhost:3000/callback",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    },
    headers={"Content-Type": "application/x-www-form-urlencoded"})
d = expect(r, 200, "ok")
if not d:
    sys.exit(1)

data = d.get("data", d)
access_token = data.get("access_token", "")
id_token = data.get("id_token", "")
refresh_token = data.get("refresh_token", "")
token_type = data.get("token_type", "")
expires_in = data.get("expires_in", 0)

if not access_token or not id_token:
    print(f"{FAIL} token 响应缺少必要字段")
    sys.exit(1)
print(f"{OK} access_token:  {access_token[:40]}...")
print(f"{OK} id_token:      {id_token[:40]}...")
print(f"{OK} refresh_token: {refresh_token[:16]}...")
print(f"{OK} token_type:    {token_type}")
print(f"{OK} expires_in:    {expires_in}s")
print()


# ============================================================
# Step 5 — UserInfo（用 access_token）
# ============================================================
print("--- Step 5: UserInfo ---")

r = requests.get(f"{AUTH_BASE}/userinfo",
    headers={"Authorization": f"Bearer {access_token}"})
d = expect(r, 200, "ok")
if d:
    claims = d.get("data", d)
    print(f"{OK} sub:               {claims.get('sub')}")
    print(f"{OK} name:              {claims.get('name')}")
    print(f"{OK} preferred_username: {claims.get('preferred_username')}")
    print(f"{OK} email:             {claims.get('email')}")
print()


# ============================================================
# Step 6 — Refresh Token 轮换
# ============================================================
print("--- Step 6: Refresh Token 轮换 ---")

r = requests.post(f"{AUTH_BASE}/token",
    data={
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    },
    headers={"Content-Type": "application/x-www-form-urlencoded"})
d = expect(r, 200, "ok")
if d:
    data = d.get("data", d)
    new_at = data.get("access_token", "")
    new_rt = data.get("refresh_token", "")
    if new_at and new_rt:
        print(f"{OK} access_token:  {new_at[:40]}...")
        print(f"{OK} refresh_token: {new_rt[:16]}... (已轮换)")
    else:
        print(f"{FAIL} refresh 响应缺少 token")
print()


# ============================================================
# Step 7 — 旧 refresh_token 应已失效
# ============================================================
print("--- Step 7: 旧 refresh_token 应已失效 ---")

r = requests.post(f"{AUTH_BASE}/token",
    data={
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,  # 旧 token（已轮换）
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    },
    headers={"Content-Type": "application/x-www-form-urlencoded"})
if r.status_code == 400:
    print(f"{OK} 旧 refresh_token 已被拒绝 (符合轮换预期)")
else:
    print(f"{FAIL} 旧 refresh_token 返回 {r.status_code}: {r.text[:100]}")
print()


# ============================================================
# 汇总
# ============================================================
print("=" * 60)
print("全部测试通过 ✅")
print("=" * 60)
