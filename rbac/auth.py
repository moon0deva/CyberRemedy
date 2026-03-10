"""
CyberRemedy RBAC — Role-Based Access Control
Supports: admin, analyst, viewer, readonly roles.
API key management, multi-tenant namespace isolation.
"""

import json
import secrets
import hashlib
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("cyberremedy.rbac")

USERS_PATH = Path("data/users.json")

# ─── PERMISSIONS ──────────────────────────────────────────────────────────────

ROLE_PERMISSIONS = {
    "admin": {
        "alerts": ["read", "write", "delete"],
        "cases": ["read", "write", "delete", "assign"],
        "blocks": ["read", "write", "delete"],
        "config": ["read", "write"],
        "users": ["read", "write", "delete"],
        "reports": ["read", "write"],
        "playbooks": ["read", "write", "execute"],
        "iocs": ["read", "write", "delete"],
        "vuln": ["read", "write"],
        "compliance": ["read"],
    },
    "analyst": {
        "alerts": ["read", "write"],
        "cases": ["read", "write", "assign"],
        "blocks": ["read", "write"],
        "config": ["read"],
        "users": ["read"],
        "reports": ["read", "write"],
        "playbooks": ["read", "execute"],
        "iocs": ["read", "write"],
        "vuln": ["read"],
        "compliance": ["read"],
    },
    "viewer": {
        "alerts": ["read"],
        "cases": ["read"],
        "blocks": ["read"],
        "config": [],
        "users": [],
        "reports": ["read"],
        "playbooks": ["read"],
        "iocs": ["read"],
        "vuln": ["read"],
        "compliance": ["read"],
    },
    "readonly": {
        "alerts": ["read"],
        "cases": ["read"],
        "blocks": ["read"],
        "config": [],
        "users": [],
        "reports": ["read"],
        "playbooks": [],
        "iocs": ["read"],
        "vuln": ["read"],
        "compliance": ["read"],
    },
}


# ─── USER ─────────────────────────────────────────────────────────────────────

class User:
    def __init__(self, username: str, role: str = "viewer",
                 tenant_id: str = "default", email: str = ""):
        self.username = username
        self.role = role
        self.tenant_id = tenant_id
        self.email = email
        self.api_keys: List[str] = []
        self.created_at = datetime.utcnow().isoformat()
        self.last_login: Optional[str] = None
        self.active = True
        self._password_hash: str = ""

    def set_password(self, password: str):
        salt = secrets.token_hex(16)
        self._password_hash = salt + ":" + hashlib.sha256(
            (salt + password).encode()).hexdigest()

    def check_password(self, password: str) -> bool:
        if not self._password_hash:
            return False
        salt, stored_hash = self._password_hash.split(":", 1)
        return hashlib.sha256((salt + password).encode()).hexdigest() == stored_hash

    def generate_api_key(self) -> str:
        key = f"cyberremedy_{secrets.token_urlsafe(32)}"
        self.api_keys.append(hashlib.sha256(key.encode()).hexdigest())
        return key  # Return raw key once (not stored)

    def has_permission(self, resource: str, action: str) -> bool:
        perms = ROLE_PERMISSIONS.get(self.role, {})
        return action in perms.get(resource, [])

    def to_dict(self, include_sensitive: bool = False) -> dict:
        d = {
            "username": self.username,
            "role": self.role,
            "tenant_id": self.tenant_id,
            "email": self.email,
            "created_at": self.created_at,
            "last_login": self.last_login,
            "active": self.active,
            "api_key_count": len(self.api_keys),
            "permissions": ROLE_PERMISSIONS.get(self.role, {}),
        }
        if include_sensitive:
            d["password_hash"] = self._password_hash
            d["api_key_hashes"] = self.api_keys
        return d

    @staticmethod
    def from_dict(d: dict) -> "User":
        u = User(d["username"], d.get("role", "viewer"),
                 d.get("tenant_id", "default"), d.get("email", ""))
        u.created_at = d.get("created_at", u.created_at)
        u.last_login = d.get("last_login")
        u.active = d.get("active", True)
        u._password_hash = d.get("password_hash", "")
        u.api_keys = d.get("api_key_hashes", [])
        return u


# ─── RBAC MANAGER ─────────────────────────────────────────────────────────────

class RBACManager:
    def __init__(self):
        self._users: Dict[str, User] = {}
        self._key_to_user: Dict[str, str] = {}   # key_hash → username
        self._load()
        if not self._users:
            self._create_default_admin()

    def _load(self):
        if USERS_PATH.exists():
            try:
                data = json.loads(USERS_PATH.read_text())
                for d in data:
                    u = User.from_dict(d)
                    self._users[u.username] = u
                    for kh in u.api_keys:
                        self._key_to_user[kh] = u.username
                logger.info(f"RBAC: {len(self._users)} users loaded")
            except Exception as e:
                logger.warning(f"RBAC load error: {e}")

    def _save(self):
        USERS_PATH.parent.mkdir(parents=True, exist_ok=True)
        data = [u.to_dict(include_sensitive=True) for u in self._users.values()]
        USERS_PATH.write_text(json.dumps(data, indent=2))

    def _create_default_admin(self):
        admin = User("admin", "admin", "default", "admin@cyberremedy.local")
        admin.set_password("cyberremedy_admin_2025")
        raw_key = admin.generate_api_key()
        self._users["admin"] = admin
        for kh in admin.api_keys:
            self._key_to_user[kh] = "admin"
        self._save()
        logger.warning(f"Default admin created. API key: {raw_key[:20]}... (change in production!)")

    def create_user(self, username: str, password: str, role: str = "viewer",
                    tenant_id: str = "default", email: str = "") -> User:
        if username in self._users:
            raise ValueError(f"User '{username}' already exists")
        u = User(username, role, tenant_id, email)
        u.set_password(password)
        self._users[username] = u
        self._save()
        return u

    def authenticate(self, username: str, password: str) -> Optional[User]:
        u = self._users.get(username)
        if u and u.active and u.check_password(password):
            u.last_login = datetime.utcnow().isoformat()
            self._save()
            return u
        return None

    def authenticate_api_key(self, raw_key: str) -> Optional[User]:
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        username = self._key_to_user.get(key_hash)
        if username:
            u = self._users.get(username)
            if u and u.active:
                u.last_login = datetime.utcnow().isoformat()
                return u
        return None

    def generate_key_for_user(self, username: str) -> Optional[str]:
        u = self._users.get(username)
        if not u:
            return None
        raw_key = u.generate_api_key()
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        self._key_to_user[key_hash] = username
        self._save()
        return raw_key

    def check_permission(self, username: str, resource: str, action: str) -> bool:
        u = self._users.get(username)
        if not u or not u.active:
            return False
        return u.has_permission(resource, action)

    def list_users(self, tenant_id: str = None) -> List[dict]:
        users = list(self._users.values())
        if tenant_id:
            users = [u for u in users if u.tenant_id == tenant_id]
        return [u.to_dict() for u in users]

    def update_role(self, username: str, new_role: str) -> bool:
        u = self._users.get(username)
        if not u or new_role not in ROLE_PERMISSIONS:
            return False
        u.role = new_role
        self._save()
        return True

    def deactivate_user(self, username: str) -> bool:
        u = self._users.get(username)
        if not u:
            return False
        u.active = False
        self._save()
        return True

    def stats(self) -> dict:
        users = list(self._users.values())
        by_role = {}
        for u in users:
            by_role[u.role] = by_role.get(u.role, 0) + 1
        return {
            "total_users": len(users),
            "active_users": sum(1 for u in users if u.active),
            "by_role": by_role,
        }
