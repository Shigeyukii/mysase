"""
セッション管理モジュール
- JWT IDI (jti) をキーにしたインメモリセッションストア
- クライアントIPの動的割り当て (10.100.0.2〜254)
- DTLSゲートウェイへの切断通知 (ファイルベースIPC)

試作版: マルチプロセス間で共有しない。
本番環境では Redis 等の共有ストアに置き換えること。
"""

import os
import ipaddress
import threading
import logging
from datetime import datetime, timezone

logger = logging.getLogger("ztna.session")

# ─────────────────────────────────────────────
# セッションストア
# { jti: SessionInfo }
# ─────────────────────────────────────────────

class SessionInfo:
    __slots__ = ("jti", "username", "client_addr", "connected_at", "tunnel_ip")

    def __init__(self, jti: str, username: str, client_addr: str, tunnel_ip: str):
        self.jti          = jti
        self.username     = username
        self.client_addr  = client_addr
        self.connected_at = datetime.now(timezone.utc).isoformat()
        self.tunnel_ip    = tunnel_ip

    def to_dict(self) -> dict:
        return {
            "jti":          self.jti[:8] + "...",
            "username":     self.username,
            "client_addr":  self.client_addr,
            "connected_at": self.connected_at,
            "tunnel_ip":    self.tunnel_ip,
        }


class SessionStore:
    """スレッドセーフなインメモリセッションストア"""

    def __init__(self, ip_pool_cidr: str, server_tunnel_ip: str):
        self._lock    = threading.Lock()
        self._sessions: dict[str, SessionInfo] = {}   # jti → SessionInfo
        self._ip_map:   dict[str, str]          = {}   # jti → allocated IP

        network = ipaddress.ip_network(ip_pool_cidr, strict=False)
        # サーバIPを除いたホスト一覧
        server_ip = ipaddress.ip_address(server_tunnel_ip)
        self._available_ips: list[str] = [
            str(h) for h in network.hosts() if h != server_ip
        ]

    # ── セッション操作 ──────────────────────────────────────────

    def create(self, jti: str, username: str, client_addr: str) -> SessionInfo:
        """セッションを作成し、トンネルIPを割り当てる"""
        with self._lock:
            if jti in self._sessions:
                return self._sessions[jti]

            tunnel_ip = self._allocate_ip_locked(jti)
            session = SessionInfo(
                jti=jti,
                username=username,
                client_addr=client_addr,
                tunnel_ip=tunnel_ip,
            )
            self._sessions[jti] = session
            logger.info(
                "Session created: user=%s jti=%s ip=%s",
                username, jti[:8], tunnel_ip,
            )
            return session

    def get(self, jti: str) -> SessionInfo | None:
        with self._lock:
            return self._sessions.get(jti)

    def delete(self, jti: str) -> SessionInfo | None:
        """セッションを削除し、IPを解放する"""
        with self._lock:
            session = self._sessions.pop(jti, None)
            if session:
                self._release_ip_locked(jti)
                logger.info(
                    "Session deleted: user=%s jti=%s",
                    session.username, jti[:8],
                )
            return session

    def list_all(self) -> list[dict]:
        with self._lock:
            return [s.to_dict() for s in self._sessions.values()]

    def count(self) -> int:
        with self._lock:
            return len(self._sessions)

    # ── IP割り当て (内部, ロック済み状態で呼ぶこと) ───────────

    def _allocate_ip_locked(self, jti: str) -> str:
        if jti in self._ip_map:
            return self._ip_map[jti]
        used = set(self._ip_map.values())
        for ip in self._available_ips:
            if ip not in used:
                self._ip_map[jti] = ip
                return ip
        raise RuntimeError("IP pool exhausted")

    def _release_ip_locked(self, jti: str):
        self._ip_map.pop(jti, None)

    # ── DTLSゲートウェイへの切断通知 ─────────────────────────

    DISCONNECT_DIR = "/tmp/ztna_disconnect"

    def notify_disconnect(self, jti: str):
        """ファイルを作成してDTLSゲートウェイに切断を通知する"""
        os.makedirs(self.DISCONNECT_DIR, exist_ok=True)
        marker = os.path.join(self.DISCONNECT_DIR, jti)
        with open(marker, "w") as f:
            f.write(jti)
        logger.debug("Disconnect marker created: jti=%s", jti[:8])
