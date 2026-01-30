# services/security_service.py
from __future__ import annotations
import json, os, hashlib
from pathlib import Path

class SecurityService:
    def __init__(self, users_json_path: str | Path = "configs/security/users.json"):
        self._users_path = Path(users_json_path)
        # Ensure file exists so QFileSystemWatcher won't fail
        if not self._users_path.exists():
            self.save({"version": 1, "users": []})

    @property
    def users_json_path(self) -> Path:
        """Compatibility: return path to users.json."""
        return self._users_path

    # ---------- core I/O ----------
    def load(self) -> dict:
        """Always return a valid dict, fallback to empty skeleton if missing/corrupted."""
        p = self._users_path
        try:
            if not p.exists() or p.stat().st_size == 0:
                return {"version": 1, "users": []}
            data = json.loads(p.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                return {"version": 1, "users": []}
            if not isinstance(data.get("users"), list):
                data["users"] = []
            return data
        except Exception:
            return {"version": 1, "users": []}

    def save(self, data: dict):
        """Atomic write to avoid partial files."""
        p = self._users_path
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, p)

    # ---------- public APIs ----------
    def list_usernames(self) -> list[str]:
        return [u.get("username", "") for u in self.load().get("users", []) if isinstance(u, dict)]

    def get_role(self, username: str) -> str | None:
        for u in self.load().get("users", []):
            if u.get("username") == username:
                return u.get("role")
        return None

    def verify(self, username: str, password: str) -> bool:
        for u in self.load().get("users", []):
            if u.get("username") == username:
                stored = u.get("password", "")
                # empty password -> stored == "" and password == ""
                return (stored == "" if password == "" else stored == password)
        return False

    def create_user(self, username: str, password: str, role: str = "operator", description: str = "") -> tuple[bool, str]:
        """Create new user (accept empty password)."""
        data = self.load()
        users = data.get("users", [])

        if any(u.get("username") == username for u in users):
            return False, f"User '{username}' already exists."

        users.append({
            "username": username,
            "role": role,
            "password": password if password else "",
            **({"description": description} if description else {})
        })
        data["users"] = users

        try:
            self.save(data)
            return True, f"User '{username}' created."
        except Exception as e:
            return False, f"Cannot save users DB: {e}"

    def update_role(self, username: str, role: str) -> tuple[bool, str]:
        """
        Update user's role and persist to users.json.
        Role must be either 'administrator' or 'operator'.
        Returns (ok, message).
        """
        role = (role or "").strip().lower()
        if role not in {"administrator", "operator"}:
            return False, "Invalid role. Must be 'administrator' or 'operator'."

        data = self.load()
        users = data.get("users", [])
        for u in users:
            if u.get("username") == username:
                u["role"] = role
                try:
                    self.save(data)
                    return True, f"Updated '{username}' to role '{role}'."
                except Exception as e:
                    return False, f"Cannot save users DB: {e}"
        return False, f"User '{username}' not found."

    # ---------- NEW: manager operations ----------
    def delete_user(self, username: str) -> tuple[bool, str | None]:
        """Delete a user by username (cannot prevent caller's special rules)."""
        data = self.load()
        users = data.get("users", [])
        new_users = [u for u in users if u.get("username") != username]
        if len(new_users) == len(users):
            return False, "User not found."
        data["users"] = new_users
        try:
            self.save(data)
            return True, f"User '{username}' deleted."
        except Exception as e:
            return False, f"Cannot save users DB: {e}"

    def update_password(self, username: str, new_password: str) -> tuple[bool, str | None]:
        """Update user's password (allow empty password)."""
        data = self.load()
        users = data.get("users", [])
        for u in users:
            if u.get("username") == username:
                u["password"] = new_password if new_password else ""
                try:
                    self.save(data)
                    return True, "Password updated."
                except Exception as e:
                    return False, f"Cannot save users DB: {e}"
        return False, "User not found."
