# utils/crypto_utils.py
from cryptography.fernet import Fernet
import keyring
from config import FERNET_KEY_NAME

def get_or_create_key():
    # Try to fetch from OS keyring (safer than storing plaintext)
    key = keyring.get_password("mini_hids", FERNET_KEY_NAME)
    if key:
        return key.encode()
    new_key = Fernet.generate_key()
    keyring.set_password("mini_hids", FERNET_KEY_NAME, new_key.decode())
    return new_key

def get_fernet():
    key = get_or_create_key()
    return Fernet(key)

