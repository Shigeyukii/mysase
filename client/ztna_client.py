"""
ZTNA Windowsクライアント (DTLS対応版)
使い方:
  python ztna_client.py login   # ログイン・トンネル確立
  python ztna_client.py logout  # ログアウト・トンネル切断
  python ztna_client.py status  # 接続状態確認

前提:
  - certs/ フォルダに ca.crt, client.crt, client.key を配置
  - pip install requests PyJWT pyopenssl dtls
  - 管理者権限で実行すること (TAPデバイス操作のため)
"""

import os
import sys
import ssl
import json
import socket
import threading
import getpass
import logging
import argparse
import struct
import ipaddress

import requests

# PyDTLS (pip install dtls)
try:
    from dtls import do_patch
    do_patch()
except ImportError:
    print("[ERROR] dtls パッケージが見つかりません: pip install dtls")
    sys.exit(1)

# ── 設定 ──────────────────────────────────────────────────────
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
CERTS_DIR   = os.path.join(SCRIPT_DIR, "certs")
STATE_FILE  = os.path.join(SCRIPT_DIR, ".ztna_state.json")

CA_CERT     = os.path.join(CERTS_DIR, "ca.crt")
CLIENT_CERT = os.path.join(CERTS_DIR, "client.crt")
CLIENT_KEY  = os.path.join(CERTS_DIR, "client.key")

# サーバのコントロールプレーンURL (config で上書き可)
CONFIG_FILE = os.path.join(SCRIPT_DIR, "client_config.json")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("ztna.client")

MTU = 1400


# ── クライアント設定読み込み ──────────────────────────────────

def load_client_config() -> dict:
    defaults = {
        "api_url": "https://YOUR_SERVER_IP:5000",
        "verify_ssl": False,   # 試作用: 本番はTrueに
    }
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, encoding="utf-8") as f:
            cfg = json.load(f)
        defaults.update(cfg)
    return defaults


# ── ログイン ──────────────────────────────────────────────────

def cmd_login(cfg: dict):
    print("=== ZTNA ログイン ===")
    username = input("ユーザー名: ").strip()
    password = getpass.getpass("パスワード: ")

    api_url = cfg["api_url"].rstrip("/")

    print(f"[*] {api_url} に認証中...")
    try:
        resp = requests.post(
            f"{api_url}/api/auth/login",
            json={"username": username, "password": password},
            verify=cfg.get("verify_ssl", False),
            timeout=10,
        )
    except requests.exceptions.ConnectionError as e:
        print(f"[ERROR] サーバに接続できません: {e}")
        sys.exit(1)

    if resp.status_code != 200:
        print(f"[ERROR] 認証失敗: {resp.json().get('error', 'unknown')}")
        sys.exit(1)

    data     = resp.json()
    token    = data["token"]
    dtls_cfg_r = data["dtls"]

    print(f"[OK] 認証成功。DTLS接続情報を取得しました。")
    print(f"     エンドポイント: {dtls_cfg_r['endpoint']}:{dtls_cfg_r['port']}")
    print(f"     クライアントIP: {dtls_cfg_r['client_tunnel_ip']}")

    # 状態をファイルに保存
    state = {
        "token":      token,
        "dtls":       dtls_cfg_r,
        "username":   username,
    }
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)

    print("[*] DTLSトンネルを確立中...")
    _start_tunnel(token, dtls_cfg_r)


# ── DTLSトンネル確立 ──────────────────────────────────────────

def _start_tunnel(token: str, dtls_info: dict):
    endpoint    = dtls_info["endpoint"]
    port        = dtls_info["port"]
    client_ip   = dtls_info["client_tunnel_ip"]
    server_ip   = dtls_info["server_tunnel_ip"]
    mtu         = dtls_info.get("mtu", MTU)

    # ── SSLContext (DTLS Client) ──
    ctx = ssl.SSLContext(ssl.PROTOCOL_DTLS)  # type: ignore[attr-defined]
    ctx.load_verify_locations(cafile=CA_CERT)
    ctx.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
    ctx.verify_mode = ssl.CERT_REQUIRED

    # UDPソケット
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    raw_sock.connect((endpoint, port))

    conn = ssl.wrap_socket(  # type: ignore[call-arg]
        raw_sock,
        ssl_version=ssl.PROTOCOL_DTLS,  # type: ignore[attr-defined]
        certfile=CLIENT_CERT,
        keyfile=CLIENT_KEY,
        ca_certs=CA_CERT,
        cert_reqs=ssl.CERT_REQUIRED,
        server_side=False,
    )

    # DTLSハンドシェイク
    conn.do_handshake()
    print("[OK] DTLSハンドシェイク成功")

    # JWT を送信
    conn.sendall(token.encode())

    # サーバからの応答 ("OK:<client_ip>" or "ERR:...")
    resp = conn.recv(256).decode("utf-8", errors="replace").strip()
    if not resp.startswith("OK:"):
        print(f"[ERROR] ゲートウェイ認証失敗: {resp}")
        conn.close()
        sys.exit(1)

    assigned_ip = resp[3:]
    print(f"[OK] トンネル確立完了！ 割り当てIP: {assigned_ip}")

    # ── Windows TAPデバイスの作成 ──
    tun_fd = _setup_windows_tun(assigned_ip, server_ip, mtu)
    if tun_fd is None:
        print("[WARN] TAPデバイスの自動設定をスキップ(手動設定が必要です)")
        print(f"  → 割り当てIP: {assigned_ip}/32 をTAPアダプタに手動設定してください")
    else:
        print(f"[OK] TAPデバイスにIP {assigned_ip} を設定しました")

    print("")
    print("   Ctrl+C でトンネルを切断します")
    print(f"   サーバへのpingテスト: ping {server_ip}")
    print("")

    # ── パケットリレー ──
    try:
        _relay_loop(conn, tun_fd, mtu)
    except KeyboardInterrupt:
        print("\n[*] ユーザーによる切断...")
    finally:
        conn.close()
        if tun_fd:
            _close_windows_tun(tun_fd)


def _relay_loop(conn, tun_fd, mtu: int):
    """DTLS ↔ TUN の双方向リレー (selectベース)"""
    import select

    conn_fd = conn.fileno()
    fds = [conn_fd]
    if tun_fd is not None:
        fds.append(tun_fd)

    while True:
        readable, _, _ = select.select(fds, [], [], 1.0)
        for fd in readable:
            if fd == conn_fd:
                data = conn.recv(mtu + 100)
                if not data:
                    return
                if tun_fd:
                    os.write(tun_fd, data)
            elif tun_fd and fd == tun_fd:
                data = os.read(tun_fd, mtu + 100)
                if data:
                    conn.sendall(data)


# ── Windows TAPデバイス操作 ──────────────────────────────────
# wintun または OpenVPN TAP-Windows を使用
# 試作版: netshコマンドでIPを設定する簡易実装

def _setup_windows_tun(client_ip: str, server_ip: str, mtu: int):
    """Windows TAPアダプタ (OpenVPN/wintun) を設定"""
    import subprocess

    # TAP-Windows アダプタ名 (OpenVPN インストール時の既定名)
    tap_name = "ZTNA-TAP"

    # インターフェースにIPを設定
    try:
        subprocess.run([
            "netsh", "interface", "ip", "set", "address",
            f"name={tap_name}", "static",
            client_ip, "255.255.255.0",
        ], check=True, capture_output=True)

        # サーバTUNIPへのルートを追加
        subprocess.run([
            "route", "add", server_ip, "mask", "255.255.255.255", client_ip
        ], check=True, capture_output=True)

        # TAPデバイスのFDを取得 (Windows: ファイルとして開く)
        tap_path = rf"\\.\Global\{tap_name}.tap"
        try:
            import ctypes
            GENERIC_READ_WRITE = 0xC0000000
            FILE_SHARE_ALL = 0x7
            OPEN_EXISTING = 3
            handle = ctypes.windll.kernel32.CreateFileW(
                tap_path, GENERIC_READ_WRITE, FILE_SHARE_ALL,
                None, OPEN_EXISTING, 0, None
            )
            if handle == -1:
                return None
            return handle
        except Exception:
            return None

    except subprocess.CalledProcessError as e:
        logger.warning("TAP設定失敗 (%s): %s", tap_name, e)
        return None


def _close_windows_tun(handle):
    """TAPデバイスハンドルを閉じる"""
    try:
        import ctypes
        ctypes.windll.kernel32.CloseHandle(handle)
    except Exception:
        pass


# ── ログアウト ────────────────────────────────────────────────

def cmd_logout(cfg: dict):
    if not os.path.exists(STATE_FILE):
        print("[INFO] 接続中のセッションがありません")
        return

    with open(STATE_FILE, encoding="utf-8") as f:
        state = json.load(f)

    token   = state.get("token")
    api_url = cfg["api_url"].rstrip("/")

    print("[*] ログアウト中...")
    try:
        resp = requests.post(
            f"{api_url}/api/auth/logout",
            headers={"Authorization": f"Bearer {token}"},
            verify=cfg.get("verify_ssl", False),
            timeout=10,
        )
        if resp.status_code == 200:
            print("[OK] ログアウト完了")
        else:
            print(f"[WARN] サーバ応答: {resp.status_code} {resp.text}")
    except Exception as e:
        print(f"[WARN] サーバへの切断通知に失敗 (ローカルのみクリア): {e}")

    os.remove(STATE_FILE)
    print("[OK] ローカルセッションを削除しました")


# ── ステータス確認 ────────────────────────────────────────────

def cmd_status(cfg: dict):
    if not os.path.exists(STATE_FILE):
        print("[INFO] 未接続")
        return

    with open(STATE_FILE, encoding="utf-8") as f:
        state = json.load(f)

    print("=== 接続状態 ===")
    print(f"  ユーザー:         {state.get('username')}")
    print(f"  クライアントIP:   {state.get('dtls', {}).get('client_tunnel_ip')}")
    print(f"  サーバIP:         {state.get('dtls', {}).get('server_tunnel_ip')}")
    print(f"  ゲートウェイ:     {state.get('dtls', {}).get('endpoint')}:{state.get('dtls', {}).get('port')}")


# ── エントリポイント ──────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="ZTNA DTLS クライアント",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使い方:
  python ztna_client.py login   # ログイン・トンネル確立
  python ztna_client.py logout  # ログアウト・トンネル切断
  python ztna_client.py status  # 接続状態確認
""",
    )
    parser.add_argument("command", choices=["login", "logout", "status"])
    args = parser.parse_args()

    cfg = load_client_config()

    if args.command == "login":
        cmd_login(cfg)
    elif args.command == "logout":
        cmd_logout(cfg)
    elif args.command == "status":
        cmd_status(cfg)


if __name__ == "__main__":
    main()
