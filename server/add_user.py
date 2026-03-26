#!/usr/bin/env python3
"""
ZTNA ユーザー管理スクリプト
使い方:
  python3 add_user.py           # 対話形式でユーザーを追加
  python3 add_user.py --list    # ユーザー一覧を表示
  python3 add_user.py --delete <username>  # ユーザーを削除
"""

import os
import json
import getpass
import argparse
import sys

try:
    import bcrypt
except ImportError:
    print("[ERROR] bcrypt が未インストールです: pip install bcrypt")
    sys.exit(1)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USER_DB_PATH = os.path.join(BASE_DIR, "user_db.json")

ROLES = ["user", "admin"]


def load_db() -> dict:
    if not os.path.exists(USER_DB_PATH):
        return {}
    with open(USER_DB_PATH, encoding="utf-8") as f:
        return json.load(f)


def save_db(db: dict):
    with open(USER_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)
    print(f"[OK] {USER_DB_PATH} を更新しました")


def cmd_add():
    print("=== ZTNAユーザー追加 ===")
    username = input("ユーザー名: ").strip()
    if not username:
        print("[ERROR] ユーザー名が空です")
        sys.exit(1)

    db = load_db()
    if username in db:
        overwrite = input(f"[WARN] ユーザー '{username}' は既に存在します。上書きしますか? [y/N]: ").strip().lower()
        if overwrite != "y":
            print("中止しました")
            sys.exit(0)

    while True:
        password = getpass.getpass("パスワード (8文字以上): ")
        if len(password) < 8:
            print("[ERROR] パスワードは8文字以上にしてください")
            continue
        confirm = getpass.getpass("パスワード (確認): ")
        if password != confirm:
            print("[ERROR] パスワードが一致しません")
            continue
        break

    role = input(f"ロール [{'/'.join(ROLES)}] (デフォルト: user): ").strip().lower()
    if role not in ROLES:
        role = "user"

    display_name = input("表示名 (任意): ").strip() or username

    # bcryptハッシュ生成
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()

    db[username] = {
        "password_hash": pw_hash,
        "role": role,
        "display_name": display_name,
    }
    save_db(db)
    print(f"[OK] ユーザー '{username}' (ロール: {role}) を追加しました")


def cmd_list():
    db = load_db()
    if not db:
        print("ユーザーが登録されていません")
        return
    print("=== 登録ユーザー一覧 ===")
    print(f"{'ユーザー名':<20} {'ロール':<10} {'表示名'}")
    print("-" * 50)
    for username, info in db.items():
        role = info.get("role", "user")
        display_name = info.get("display_name", username)
        print(f"{username:<20} {role:<10} {display_name}")


def cmd_delete(username: str):
    db = load_db()
    if username not in db:
        print(f"[ERROR] ユーザー '{username}' が見つかりません")
        sys.exit(1)
    confirm = input(f"ユーザー '{username}' を削除しますか? [y/N]: ").strip().lower()
    if confirm != "y":
        print("中止しました")
        return
    del db[username]
    save_db(db)
    print(f"[OK] ユーザー '{username}' を削除しました")


def main():
    parser = argparse.ArgumentParser(description="ZTNA ユーザー管理")
    parser.add_argument("--list", action="store_true", help="ユーザー一覧を表示")
    parser.add_argument("--delete", metavar="USERNAME", help="ユーザーを削除")
    args = parser.parse_args()

    if args.list:
        cmd_list()
    elif args.delete:
        cmd_delete(args.delete)
    else:
        cmd_add()


if __name__ == "__main__":
    main()
