#!/bin/bash
# ZTNA DTLSサーバ 自動インストールスクリプト (Ubuntu/Debian系)
set -e

INSTALL_DIR="/opt/ztna"
CERT_DIR="/etc/ztna/certs"
LOG_DIR="/var/log"
SERVICE_NAME="ztna-server"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "==================================================="
echo " ZTNA DTLSサーバ インストール"
echo "==================================================="

# ── 1. root確認 ──────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
  echo "[ERROR] rootで実行してください: sudo bash install.sh"
  exit 1
fi

# ── 2. システムパッケージのインストール ──────────────────────
echo "[1/6] システムパッケージをインストール中..."
apt-get update -qq
apt-get install -y -qq \
  openssl \
  python3 \
  python3-pip \
  python3-venv \
  python3-dev \
  iproute2 \
  gcc \
  libssl-dev

# ── 3. TUNカーネルモジュールの確認 ───────────────────────────
echo "[2/6] TUNカーネルモジュールを確認中..."
modprobe tun || true
if [ ! -c /dev/net/tun ]; then
  echo "[ERROR] /dev/net/tun が見つかりません。カーネルのTUNサポートが必要です。"
  exit 1
fi
echo "  → /dev/net/tun OK"

# ── 4. インストールディレクトリの準備 ────────────────────────
echo "[3/6] インストールディレクトリを準備中..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$CERT_DIR"

# サーバファイルをコピー
cp -r "$SCRIPT_DIR"/*.py "$INSTALL_DIR/"
cp "$SCRIPT_DIR/config.yaml" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/user_db.json" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/requirements.txt" "$INSTALL_DIR/"

# ── 5. Python仮想環境とパッケージのインストール ──────────────
echo "[4/6] Python仮想環境をセットアップ中..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip -q
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q
echo "  → Python packages installed"

# ── 6. 証明書の生成 ──────────────────────────────────────────
echo "[5/6] 自己署名証明書を生成中..."
CERT_SCRIPT="$(dirname "$SCRIPT_DIR")/certs/gen_certs.sh"
if [ -f "$CERT_SCRIPT" ]; then
  bash "$CERT_SCRIPT"
  cp "$(dirname "$SCRIPT_DIR")/certs/server.crt" "$CERT_DIR/"
  cp "$(dirname "$SCRIPT_DIR")/certs/server.key" "$CERT_DIR/"
  cp "$(dirname "$SCRIPT_DIR")/certs/ca.crt"    "$CERT_DIR/"
  chmod 600 "$CERT_DIR"/*.key
  echo "  → 証明書を $CERT_DIR に配置しました"
else
  echo "  [WARN] certs/gen_certs.sh が見つかりません。証明書は手動で配置してください。"
fi

# ── 7. systemdサービスの登録 ──────────────────────────────────
echo "[6/6] systemdサービスを登録中..."
cp "$SCRIPT_DIR/ztna-server.service" "/etc/systemd/system/$SERVICE_NAME.service"
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
echo "  → systemd service enabled"

echo ""
echo "==================================================="
echo " インストール完了！"
echo "==================================================="
echo ""
echo "次のステップ:"
echo "  1. $INSTALL_DIR/config.yaml を編集"
echo "     - dtls.server_endpoint に実際のIPまたはドメインを設定"
echo "     - jwt.secret_key を安全なランダム文字列に変更"
echo ""
echo "  2. ユーザーを追加:"
echo "     python3 -c \\"
echo "       \"import bcrypt, json\\"
echo "       pw = bcrypt.hashpw(b'yourpassword', bcrypt.gensalt()).decode()\\"
echo "       print(pw)\""
echo "     → 出力をuser_db.jsonのpassword_hashに設定"
echo ""
echo "  3. サービス起動:"
echo "     sudo systemctl start $SERVICE_NAME"
echo "     sudo systemctl status $SERVICE_NAME"
echo ""
echo "  4. クライアント証明書をWindowsに転送:"
echo "     $(dirname "$SCRIPT_DIR")/certs/client.crt"
echo "     $(dirname "$SCRIPT_DIR")/certs/client.key"
echo "     $(dirname "$SCRIPT_DIR")/certs/ca.crt"
