"""One-time Telegram session setup for Fortis Intelligence Hub.

Run this script to authenticate with Telegram and create a session file.
After authentication, the session persists on disk and subsequent
connections reuse it without requiring phone input.

Usage:
    python -m app.telegram_auth
"""

import asyncio
import os
import sys

from dotenv import load_dotenv

load_dotenv()


async def main() -> None:
    api_id_str = os.getenv("TELEGRAM_API_ID", "")
    api_hash = os.getenv("TELEGRAM_API_HASH", "")

    if not api_id_str or not api_hash:
        print("ERROR: TELEGRAM_API_ID and TELEGRAM_API_HASH must be set in .env")
        sys.exit(1)

    try:
        api_id = int(api_id_str)
    except ValueError:
        print("ERROR: TELEGRAM_API_ID must be an integer")
        sys.exit(1)

    session_path = os.getenv("TELEGRAM_SESSION_PATH", "data/telegram_session")

    os.makedirs(os.path.dirname(session_path) or ".", exist_ok=True)

    try:
        from telethon import TelegramClient
    except ImportError:
        print("ERROR: telethon is not installed. Run: pip install telethon")
        sys.exit(1)

    print("=" * 50)
    print("  Fortis Intelligence Hub — Telegram Setup")
    print("=" * 50)
    print()
    print(f"  Session file: {session_path}.session")
    print()

    client = TelegramClient(session_path, api_id, api_hash)
    await client.connect()

    if await client.is_user_authorized():
        me = await client.get_me()
        print(f"  Already authenticated as: {me.first_name} (@{me.username})")
        print("  Session file is valid. No action needed.")
        await client.disconnect()
        return

    phone = input("  Enter your phone number (with country code, e.g. +1234567890): ").strip()
    if not phone:
        print("  Aborted.")
        await client.disconnect()
        return

    await client.send_code_request(phone)
    code = input("  Enter the code Telegram sent you: ").strip()

    try:
        await client.sign_in(phone, code)
    except Exception:
        password = input("  Two-factor password required. Enter password: ").strip()
        await client.sign_in(password=password)

    me = await client.get_me()
    print()
    print(f"  Authenticated as: {me.first_name} (@{me.username})")
    print(f"  Session saved to: {session_path}.session")
    print()
    print("  Telegram integration is now ready. Restart the app to use it.")

    await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
