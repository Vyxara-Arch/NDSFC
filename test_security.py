import sys
import os
import json
import shutil

sys.path.append(os.getcwd())

from core.vault_manager import VaultManager
from core.auth import AuthManager


def test_security():
    print("Testing Security Fixes...")

    # Setup
    vm = VaultManager()
    am = AuthManager()
    vault_name = "test_vault_secure"
    password = "secure_password_123"
    duress = "panic_password"

    path = vm.get_vault_path(vault_name)
    if os.path.exists(path):
        os.remove(path)

    # 1. Create Vault
    print(f"[1] Creating Vault: {vault_name}")
    created, totp_secret = vm.create_vault(vault_name, "user", password, duress)
    if not created:
        print("FAILED: Could not create vault")
        return False

    print(f"    Vault created. TOTP: {totp_secret}")

    # 2. Verify File Content (Should NOT have totp_secret in plaintext)
    print(f"[2] Inspecting Vault File: {path}")
    with open(path, "r") as f:
        content = f.read()

    if totp_secret in content:
        print("CRITICAL FAIL: TOTP Secret found in plaintext in vault file!")
        return False
    else:
        print("PASS: TOTP Secret is NOT visible in plaintext.")

    if "vault_data" not in content:
        print("FAIL: 'vault_data' field missing.")
        return False

    # 3. Test Login Success
    print("[3] Testing Valid Login")
    am.set_active_vault(path)

    import pyotp

    totp = pyotp.TOTP(totp_secret)
    code = totp.now()

    success, msg = am.login(password, code)
    if success:
        print("PASS: Login Successful")
    else:
        print(f"FAIL: Login Failed: {msg}")
        return False

    # 4. Test Settings Load
    if "algo" in am.settings:
        print(f"PASS: Settings loaded correctly ({am.settings['algo']})")
    else:
        print("FAIL: Settings not loaded.")
        return False

    # Cleanup
    if os.path.exists(path):
        os.remove(path)

    return True


if __name__ == "__main__":
    if test_security():
        print("\nALL TESTS PASSED")
    else:
        print("\nTESTS FAILED")
        sys.exit(1)
