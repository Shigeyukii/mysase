"""
ZTNA Flask APIサーバ (DTLS対応版)
- POST /api/auth/login   : 認証 → JWT + DTLS接続情報を返す
- POST /api/auth/logout  : セッション終了
- GET  /api/status       : 接続中セッション一覧
"""

import os
import json
import hashlib
import logging
import yaml
import bcrypt
import jwt
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from functools import wraps

# ── 設定読み込み ──────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(BASE_DIR, "config.yaml"), encoding="utf-8") as f:
    config = yaml.safe_load(f)

jwt_cfg  = config["jwt"]
srv_cfg  = config["server"]
dtls_cfg = config["dtls"]
log_cfg  = config["logging"]

# ── ロギング ──────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, log_cfg.get("level", "INFO")),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(log_cfg.get("file", "/var/log/ztna-server.log")),
    ],
)
logger = logging.getLogger("ztna.api")

# ── Flask アプリ ──────────────────────────────────────────────
app = Flask(__name__)

# ── ユーザーDB ────────────────────────────────────────────────
USER_DB_PATH = os.path.join(BASE_DIR, "user_db.json")

def load_users():
    with open(USER_DB_PATH, encoding="utf-8") as f:
        return json.load(f)

# ── セッション管理 (メモリ, 試作用) ──────────────────────────
# { jwt_token_id: { "username": str, "client_ip": str, "connected_at": str } }
active_sessions: dict = {}

# ── 証明書フィンガープリント取得 ──────────────────────────────
def get_server_cert_fingerprint() -> str:
    cert_path = dtls_cfg["cert_path"]
    if not os.path.exists(cert_path):
        return "CERT_NOT_FOUND"
    with open(cert_path, "rb") as f:
        cert_data = f.read()
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    fp = cert.fingerprint(cert.signature_hash_algorithm)
    return fp.hex()

# ── JWT ヘルパー ──────────────────────────────────────────────
def generate_jwt(username: str) -> tuple[str, str]:
    """JWTを生成。(token, jti) を返す"""
    jti = os.urandom(16).hex()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + timedelta(hours=jwt_cfg["expiry_hours"]),
        "jti": jti,
    }
    token = jwt.encode(payload, jwt_cfg["secret_key"], algorithm=jwt_cfg["algorithm"])
    return token, jti

def require_auth(f):
    """JWT認証デコレータ"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authorization header missing"}), 401
        token = auth_header[7:]
        try:
            payload = jwt.decode(
                token,
                jwt_cfg["secret_key"],
                algorithms=[jwt_cfg["algorithm"]],
            )
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError as e:
            return jsonify({"error": f"Invalid token: {e}"}), 401
        request.jwt_payload = payload
        return f(*args, **kwargs)
    return decorated

# ── エンドポイント ────────────────────────────────────────────

@app.post("/api/auth/login")
def login():
    """認証 → JWT発行 + DTLS接続情報を返す"""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    users = load_users()
    user = users.get(username)
    if user is None:
        logger.warning("Login failed: unknown user '%s'", username)
        return jsonify({"error": "Invalid credentials"}), 401

    if not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        logger.warning("Login failed: wrong password for '%s'", username)
        return jsonify({"error": "Invalid credentials"}), 401

    token, jti = generate_jwt(username)

    # セッション登録
    active_sessions[jti] = {
        "username": username,
        "client_ip": request.remote_addr,
        "connected_at": datetime.now(timezone.utc).isoformat(),
        "jti": jti,
    }
    logger.info("Login success: user='%s' jti='%s'", username, jti)

    # DTLS接続情報
    dtls_info = {
        "endpoint": dtls_cfg["server_endpoint"],
        "port": dtls_cfg["listen_port"],
        "server_cert_fingerprint": get_server_cert_fingerprint(),
        "client_tunnel_ip": _allocate_client_ip(jti),
        "server_tunnel_ip": dtls_cfg["server_tunnel_ip"],
        "mtu": dtls_cfg.get("mtu", 1400),
    }

    return jsonify({
        "token": token,
        "expires_in": jwt_cfg["expiry_hours"] * 3600,
        "dtls": dtls_info,
    }), 200


@app.post("/api/auth/logout")
@require_auth
def logout():
    """セッション終了"""
    jti = request.jwt_payload.get("jti")
    username = request.jwt_payload.get("sub")
    session = active_sessions.pop(jti, None)
    if session:
        logger.info("Logout: user='%s' jti='%s'", username, jti)
        # DTLSゲートウェイにセッション切断を通知 (将来: IPC/REST経由)
        _notify_gateway_disconnect(jti)
    return jsonify({"status": "logged out"}), 200


@app.get("/api/status")
def status():
    """接続中セッション一覧 (管理用)"""
    sessions_info = []
    for jti, s in active_sessions.items():
        sessions_info.append({
            "username": s["username"],
            "client_ip": s["client_ip"],
            "connected_at": s["connected_at"],
            "jti": jti[:8] + "...",
        })
    return jsonify({
        "status": "ok",
        "active_sessions": len(active_sessions),
        "sessions": sessions_info,
    }), 200


# ── 内部ヘルパー ──────────────────────────────────────────────

_ip_allocations: dict = {}  # jti → allocated_ip

def _allocate_client_ip(jti: str) -> str:
    """クライアントにトンネルIPを割り当て (試作: 連番)"""
    import ipaddress
    pool = ipaddress.ip_network(dtls_cfg["client_ip_pool"])
    # .1 はサーバ用なので .2 から割り当て
    hosts = list(pool.hosts())
    used_ips = set(_ip_allocations.values())
    for host in hosts[1:]:  # hosts[0] = 10.100.0.1 (サーバ)
        ip_str = str(host)
        if ip_str not in used_ips:
            _ip_allocations[jti] = ip_str
            logger.debug("Allocated IP %s for jti=%s", ip_str, jti[:8])
            return ip_str
    raise RuntimeError("IP pool exhausted")


def _notify_gateway_disconnect(jti: str):
    """DTLSゲートウェイにセッション切断を通知 (試作: ファイル経由)"""
    disconnect_dir = "/tmp/ztna_disconnect"
    os.makedirs(disconnect_dir, exist_ok=True)
    with open(os.path.join(disconnect_dir, jti), "w") as f:
        f.write(jti)
    _ip_allocations.pop(jti, None)


# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(
        host=srv_cfg.get("host", "0.0.0.0"),
        port=srv_cfg.get("port", 5000),
        debug=srv_cfg.get("debug", False),
    )
