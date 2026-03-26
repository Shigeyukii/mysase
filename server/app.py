"""
ZTNA Flask APIサーバ (DTLS対応版)
- POST /api/auth/login   : 認証 → JWT + DTLS接続情報を返す
- POST /api/auth/logout  : セッション終了
- GET  /api/status       : 接続中セッション一覧
"""

import os
import json
import logging
import yaml
import bcrypt
import jwt
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from functools import wraps

from session_store import SessionStore

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

# ── セッションストア (session_store.py) ───────────────────────
store = SessionStore(
    ip_pool_cidr=dtls_cfg["client_ip_pool"],
    server_tunnel_ip=dtls_cfg["server_tunnel_ip"],
)

# ── ユーザーDB ────────────────────────────────────────────────
USER_DB_PATH = os.path.join(BASE_DIR, "user_db.json")

def load_users():
    with open(USER_DB_PATH, encoding="utf-8") as f:
        return json.load(f)

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

    # session_store にセッション登録 (IPも同時に割り当てられる)
    session = store.create(
        jti=jti,
        username=username,
        client_addr=request.remote_addr,
    )

    logger.info("Login success: user='%s' jti='%s' tunnel_ip='%s'", username, jti, session.tunnel_ip)

    # DTLS接続情報
    dtls_info = {
        "endpoint": dtls_cfg["server_endpoint"],
        "port": dtls_cfg["listen_port"],
        "server_cert_fingerprint": get_server_cert_fingerprint(),
        "client_tunnel_ip": session.tunnel_ip,
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

    session = store.delete(jti)
    if session:
        logger.info("Logout: user='%s' jti='%s'", username, jti)
        # DTLSゲートウェイにセッション切断を通知 (ファイルベースIPC)
        store.notify_disconnect(jti)

    return jsonify({"status": "logged out"}), 200


@app.get("/api/status")
def status():
    """接続中セッション一覧 (管理用)"""
    sessions_info = store.list_all()
    return jsonify({
        "status": "ok",
        "active_sessions": store.count(),
        "sessions": sessions_info,
    }), 200


# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(
        host=srv_cfg.get("host", "0.0.0.0"),
        port=srv_cfg.get("port", 5000),
        ssl_context=(dtls_cfg["cert_path"], dtls_cfg["key_path"]),
        debug=srv_cfg.get("debug", False),
    )
