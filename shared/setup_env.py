from __future__ import annotations

import os
import secrets
import socket


def generate_env(output_path: str = "/app/shared/config/.env") -> None:
    if os.path.exists(output_path):
        return

    api_key = secrets.token_hex(32)
    db_pass = secrets.token_hex(16)

    try:
        host_ip = socket.gethostbyname(socket.gethostname())
    except socket.gaierror:
        host_ip = "127.0.0.1"

    env_content = (
        f"WEB_APP_BH_API_KEY={api_key}\n"
        f"HOST_IP={host_ip}\n"
        f"DB_HOST=postgres\n"
        f"DB_PORT=5432\n"
        f"DB_NAME=webbh\n"
        f"DB_USER=webbh_admin\n"
        f"DB_PASS={db_pass}\n"
        f"REDIS_HOST=redis\n"
        f"REDIS_PORT=6379\n"
    )

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        f.write(env_content)

    print(f"[setup_env] API Key: {api_key}")
    print(f"[setup_env] .env written to: {output_path}")


if __name__ == "__main__":
    generate_env()
