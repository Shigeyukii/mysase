"""
TUNデバイス管理モジュール
Linux の /dev/net/tun を使ってトンネルインターフェースを作成・削除・管理します。

※ root権限が必要です。
"""

import os
import subprocess
import ipaddress
import logging
import struct
import fcntl

logger = logging.getLogger("ztna.tun")

# Linux tun/tap の ioctl 定数
TUNSETIFF   = 0x400454CA
TUNSETOWNER = 0x400454CC
IFF_TUN     = 0x0001
IFF_NO_PI   = 0x1000

# 管理中のTUNデバイス { jti -> { "name": str, "ip": str, "fd": int } }
_active_tuns: dict = {}


def create_tun(jti: str, client_ip: str, server_ip: str, mtu: int = 1400) -> str:
    """
    TUNデバイスを作成してIPを設定する。
    Returns: TUNデバイス名 (例: "tun0")
    """
    if jti in _active_tuns:
        return _active_tuns[jti]["name"]

    # /dev/net/tun を開く
    tun_fd = os.open("/dev/net/tun", os.O_RDWR)

    # インターフェース名を決定 (tun10 - tun254)
    dev_name = _pick_tun_name()
    dev_name_bytes = dev_name.encode("utf-8")

    # TUNSETIFF ioctl
    ifr = struct.pack("16sH", dev_name_bytes, IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(tun_fd, TUNSETIFF, ifr)

    _active_tuns[jti] = {
        "name": dev_name,
        "ip":   client_ip,
        "fd":   tun_fd,
    }

    # IPアドレス設定とリンクアップ
    _run(["ip", "addr", "add", f"{client_ip}/32", "dev", dev_name])
    _run(["ip", "link", "set", dev_name, "up", "mtu", str(mtu)])

    # クライアントIPへのルートを追加
    _run(["ip", "route", "add", f"{client_ip}/32", "dev", dev_name])

    logger.info("TUN created: dev=%s client_ip=%s jti=%s", dev_name, client_ip, jti[:8])
    return dev_name


def delete_tun(jti: str):
    """TUNデバイスを削除してIPルートを解放する"""
    info = _active_tuns.pop(jti, None)
    if info is None:
        return

    dev_name = info["name"]
    client_ip = info["ip"]
    tun_fd = info["fd"]

    try:
        _run(["ip", "link", "set", dev_name, "down"])
    except Exception:
        pass
    try:
        _run(["ip", "route", "del", f"{client_ip}/32"])
    except Exception:
        pass
    try:
        os.close(tun_fd)
    except Exception:
        pass

    logger.info("TUN deleted: dev=%s jti=%s", dev_name, jti[:8])


def get_tun_fd(jti: str) -> int | None:
    """指定セッションのTUNファイルディスクリプタを返す"""
    info = _active_tuns.get(jti)
    return info["fd"] if info else None


def get_tun_name(jti: str) -> str | None:
    info = _active_tuns.get(jti)
    return info["name"] if info else None


def list_active_tuns() -> list[dict]:
    return [
        {"jti": jti[:8] + "...", "dev": v["name"], "client_ip": v["ip"]}
        for jti, v in _active_tuns.items()
    ]


# ── 内部ヘルパー ──────────────────────────────────────────────

def _pick_tun_name() -> str:
    """使用中でないtunデバイス名を探す"""
    used = {v["name"] for v in _active_tuns.values()}
    for i in range(10, 255):
        name = f"tun{i}"
        if name not in used:
            return name
    raise RuntimeError("No available TUN device name")


def _run(cmd: list[str]):
    """コマンドを実行。失敗時は例外を送出"""
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed: {' '.join(cmd)}\n"
            f"stderr: {result.stderr.strip()}"
        )
