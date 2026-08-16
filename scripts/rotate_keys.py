from app.database import SessionLocal, init_db
from app.services.rotation import rotate_rsa_wrapping_key
from app.state import key_manager

if __name__ == "__main__":
    init_db()
    key_manager.ensure_initialized()
    with SessionLocal() as db:
        stats = rotate_rsa_wrapping_key(db)
    print(
        f"Rotation completed: {stats.new_key_id}; "
        f"users={stats.users_rewrapped}; records={stats.records_rewrapped}"
    )
