#!/bin/bash
# ZTNA DTLS 証明書生成スクリプト
# 自己署名CA, サーバ証明書, クライアント証明書を生成します

set -e

CERT_DIR="$(cd "$(dirname "$0")" && pwd)"
DAYS=3650   # 10年有効

echo "=== ZTNA DTLS 証明書生成 ==="
echo "出力先: $CERT_DIR"

# ---- 1. CA (認証局) ----
echo "[1/3] CA 秘密鍵・証明書を生成中..."
openssl genrsa -out "$CERT_DIR/ca.key" 4096 2>/dev/null
openssl req -new -x509 -days $DAYS \
  -key "$CERT_DIR/ca.key" \
  -out "$CERT_DIR/ca.crt" \
  -subj "/CN=ZTNA-CA/O=MySASE/C=JP"

# ---- 2. サーバ証明書 ----
echo "[2/3] サーバ証明書を生成中..."
openssl genrsa -out "$CERT_DIR/server.key" 2048 2>/dev/null
openssl req -new \
  -key "$CERT_DIR/server.key" \
  -out "$CERT_DIR/server.csr" \
  -subj "/CN=ztna-server/O=MySASE/C=JP"

# SAN (Subject Alternative Name) 拡張
cat > "$CERT_DIR/server_ext.cnf" <<EOF
[req]
req_extensions = v3_req
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = ztna-server
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 -req -days $DAYS \
  -in "$CERT_DIR/server.csr" \
  -CA "$CERT_DIR/ca.crt" \
  -CAkey "$CERT_DIR/ca.key" \
  -CAcreateserial \
  -out "$CERT_DIR/server.crt" \
  -extfile "$CERT_DIR/server_ext.cnf" \
  -extensions v3_req 2>/dev/null

# ---- 3. クライアント証明書 ----
echo "[3/3] クライアント証明書を生成中..."
openssl genrsa -out "$CERT_DIR/client.key" 2048 2>/dev/null
openssl req -new \
  -key "$CERT_DIR/client.key" \
  -out "$CERT_DIR/client.csr" \
  -subj "/CN=ztna-client/O=MySASE/C=JP"
openssl x509 -req -days $DAYS \
  -in "$CERT_DIR/client.csr" \
  -CA "$CERT_DIR/ca.crt" \
  -CAkey "$CERT_DIR/ca.key" \
  -CAcreateserial \
  -out "$CERT_DIR/client.crt" 2>/dev/null

# 一時ファイル削除
rm -f "$CERT_DIR"/*.csr "$CERT_DIR/server_ext.cnf"

# 秘密鍵のパーミッション設定
chmod 600 "$CERT_DIR"/*.key

echo ""
echo "=== 生成完了 ==="
ls -la "$CERT_DIR"/*.crt "$CERT_DIR"/*.key
echo ""
echo "次のステップ:"
echo "  - server.crt, server.key → Linuxサーバの /etc/ztna/certs/ に配置"
echo "  - client.crt, client.key → Windowsクライアントのcertsフォルダに配置"
echo "  - ca.crt → 両方に配置"
