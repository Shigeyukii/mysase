"""
DTLSゲートウェイ (データプレーン)
PyDTLS (dtls パッケージ) を使いUDP上でDTLS 1.2トンネルを確立します。

動作概要:
  1. UDPソケットをリッスン
  2. クライアントからDTLSハンドシェイクを受け付ける（相互TLS認証）
  3. 認証されたクライアントのパケットをTUNデバイスに転送
  4. TUNデバイスからの応答パケットをクライアントに返す

実行: sudo python3 dtls_gateway.py
      (root権限が必要: TUNデバイス操作のため)
"""

import os
import sys
import ssl
import socket
import select
import threading
import logging
import signal
import yaml
import jwt

# PyDTLS (pip install dtls)
try:
    from dtls import do_patch
    do_patch()   # ssl モジュールにDTLSサポートを注入
except ImportError:
    print("[ERROR] dtls パッケージが見つかりません: pip install dtls")
    sys.exit(1)

import tun_manager

# ── 設定読み込み ──────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(BASE_DIR, "config.yaml"), encoding="utf-8") as f:
    config = yaml.safe_load(f)

jwt_cfg  = config["jwt"]
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
logger = logging.getLogger("ztna.gateway")

# ── セッション管理 ────────────────────────────────────────────
# addr (host, port) → { "jti": str, "username": str, "conn": ssl.SSLSocket }
_sessions: dict = {}
_sessions_lock = threading.Lock()

DISCONNECT_DIR = "/tmp/ztna_disconnect"
MTU = dtls_cfg.get("mtu", 1400)


# ── DTLSサーバ本体 ────────────────────────────────────────────

class DTLSGateway:
    def __init__(self):
        self.cert_path   = dtls_cfg["cert_path"]
        self.key_path    = dtls_cfg["key_path"]
        self.ca_cert     = dtls_cfg["ca_cert_path"]
        self.host        = dtls_cfg["listen_host"]
        self.port        = dtls_cfg["listen_port"]
        self.server_ip   = dtls_cfg["server_tunnel_ip"]
        self.running     = False
        self._threads: list[threading.Thread] = []

    def _make_ssl_context(self) -> ssl.SSLContext:
        """DTLSサーバ用SSLContextを生成 (相互TLS認証)"""
        # DTLS_SERVER は PyDTLS が do_patch() で追加する定数
        ctx = ssl.SSLContext(ssl.PROTOCOL_DTLS_SERVER)  # type: ignore[attr-defined]
        ctx.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)
        ctx.load_verify_locations(cafile=self.ca_cert)
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    def start(self):
        """メインループを開始"""
        ctx = self._make_ssl_context()

        # UDPソケット作成 (DTLS はUDPの上で動く)
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_sock.bind((self.host, self.port))

        # DTLSサーバとしてラップ
        # PyDTLS は ssl.wrap_socket と同じインターフェースでDTLSを提供
        server_sock = ssl.wrap_socket(  # type: ignore[call-arg]
            raw_sock,
            server_side=True,
            ssl_version=ssl.PROTOCOL_DTLS,  # type: ignore[attr-defined]
            certfile=self.cert_path,
            keyfile=self.key_path,
            ca_certs=self.ca_cert,
            cert_reqs=ssl.CERT_REQUIRED,
        )

        self.running = True
        logger.info(
            "DTLS Gateway listening on UDP %s:%d", self.host, self.port
        )

        # 切断監視スレッド起動
        disconnect_thread = threading.Thread(
            target=self._watch_disconnects, daemon=True
        )
        disconnect_thread.start()

        while self.running:
            try:
                ready, _, _ = select.select([server_sock], [], [], 1.0)
                if not ready:
                    continue

                # 新しいクライアントからの接続を受け付け
                conn, addr = server_sock.accept()
                logger.info("New DTLS connection from %s:%d", *addr)

                # クライアント証明書の検証 (accept()後に自動済み)
                client_cert = conn.getpeercert()
                if not client_cert:
                    logger.warning("Client cert missing, closing %s:%d", *addr)
                    conn.close()
                    continue

                # ハンドラスレッド起動
                t = threading.Thread(
                    target=self._handle_client,
                    args=(conn, addr),
                    daemon=True,
                )
                t.start()
                self._threads.append(t)

            except Exception as e:
                if self.running:
                    logger.error("Accept error: %s", e)

        server_sock.close()
        logger.info("DTLS Gateway stopped.")

    def _handle_client(self, conn: ssl.SSLSocket, addr: tuple):
        """
        クライアントとのDTLSセッションを処理するスレッド。

        プロトコル:
          [接続直後] クライアントが JWT を平文で送信
          [サーバ]   JWTを検証してセッション確立。"OK:<client_ip>" を返す
          [以降]     L3パケットをそのままリレー
        """
        try:
            # ── 1. JWT 受信・検証 ──
            raw = conn.recv(4096)
            if not raw:
                conn.close()
                return

            token = raw.decode("utf-8", errors="replace").strip()
            try:
                payload = jwt.decode(
                    token,
                    jwt_cfg["secret_key"],
                    algorithms=[jwt_cfg["algorithm"]],
                )
            except jwt.ExpiredSignatureError:
                conn.sendall(b"ERR:token_expired")
                conn.close()
                return
            except jwt.InvalidTokenError as e:
                conn.sendall(f"ERR:invalid_token:{e}".encode())
                conn.close()
                return

            jti      = payload["jti"]
            username = payload["sub"]

            # ── 2. TUNデバイス作成 ──
            # client_ip は app.py の _allocate_client_ip と同じロジックで割り当て済み
            # ここでは jti をキーに採番 (gateway側でも同様に採番)
            client_ip = _simple_allocate_ip(jti)
            tun_fd_val = tun_manager.create_tun(jti, client_ip, self.server_ip, MTU)

            # ── 3. セッション登録 ──
            with _sessions_lock:
                _sessions[addr] = {
                    "jti": jti,
                    "username": username,
                    "conn": conn,
                    "client_ip": client_ip,
                    "tun_name": tun_fd_val,
                }
            logger.info(
                "Session established: user=%s jti=%s client_ip=%s",
                username, jti[:8], client_ip
            )

            # ── 4. "OK:<client_ip>" を返す ──
            conn.sendall(f"OK:{client_ip}".encode())

            # ── 5. パケットリレー (双方向) ──
            tun_fd = tun_manager.get_tun_fd(jti)
            self._relay(conn, tun_fd, jti)

        except Exception as e:
            logger.error("Client handler error %s:%d : %s", *addr, e)
        finally:
            self._cleanup_session(addr)

    def _relay(self, conn: ssl.SSLSocket, tun_fd: int, jti: str):
        """DTLS↔TUN の双方向パケットリレー"""
        conn_fd = conn.fileno()

        while self.running:
            # 切断ファイル監視
            if _check_disconnect_file(jti):
                logger.info("Disconnect requested for jti=%s", jti[:8])
                break

            try:
                readable, _, _ = select.select([conn_fd, tun_fd], [], [], 1.0)
            except Exception:
                break

            for fd in readable:
                if fd == conn_fd:
                    # DTLS → TUN
                    try:
                        data = conn.recv(MTU + 100)
                        if not data:
                            return
                        os.write(tun_fd, data)
                    except Exception:
                        return
                elif fd == tun_fd:
                    # TUN → DTLS
                    try:
                        data = os.read(tun_fd, MTU + 100)
                        if data:
                            conn.sendall(data)
                    except Exception:
                        return

    def _cleanup_session(self, addr: tuple):
        """セッションをクリーンアップ"""
        with _sessions_lock:
            session = _sessions.pop(addr, None)
        if session:
            jti = session["jti"]
            tun_manager.delete_tun(jti)
            try:
                session["conn"].close()
            except Exception:
                pass
            logger.info("Session cleaned up: jti=%s", jti[:8])

    def _watch_disconnects(self):
        """app.py からの切断ファイルを監視してセッションを終了"""
        os.makedirs(DISCONNECT_DIR, exist_ok=True)
        while self.running:
            try:
                for fname in os.listdir(DISCONNECT_DIR):
                    jti = fname
                    fpath = os.path.join(DISCONNECT_DIR, fname)
                    logger.info("Disconnect file found: jti=%s", jti[:8])
                    # 対応するセッションを探して切断
                    with _sessions_lock:
                        targets = [
                            (addr, s) for addr, s in _sessions.items()
                            if s["jti"] == jti
                        ]
                    for addr, s in targets:
                        try:
                            s["conn"].close()
                        except Exception:
                            pass
                    os.remove(fpath)
            except Exception as e:
                logger.debug("Watch disconnects error: %s", e)
            threading.Event().wait(2.0)

    def stop(self):
        self.running = False


# ── IP割り当て (ゲートウェイ側簡易版) ────────────────────────
import ipaddress as _ipmod

_gw_ip_map: dict = {}

def _simple_allocate_ip(jti: str) -> str:
    if jti in _gw_ip_map:
        return _gw_ip_map[jti]
    pool = _ipmod.ip_network(dtls_cfg["client_ip_pool"])
    used = set(_gw_ip_map.values())
    # .1 はサーバ用
    for host in list(pool.hosts())[1:]:
        s = str(host)
        if s not in used:
            _gw_ip_map[jti] = s
            return s
    raise RuntimeError("IP pool exhausted")


def _check_disconnect_file(jti: str) -> bool:
    return os.path.exists(os.path.join(DISCONNECT_DIR, jti))


# ── エントリポイント ──────────────────────────────────────────

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[ERROR] root権限で実行してください: sudo python3 dtls_gateway.py")
        sys.exit(1)

    gw = DTLSGateway()

    def _handle_signal(sig, frame):
        logger.info("Shutting down DTLS gateway...")
        gw.stop()

    signal.signal(signal.SIGINT,  _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    gw.start()
