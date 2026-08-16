from app.state import key_manager

if __name__ == "__main__":
    key_manager.ensure_initialized()
    print(f"Active RSA key: {key_manager.active_key_id}")
