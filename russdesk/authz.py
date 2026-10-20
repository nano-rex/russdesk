"""Who may do what: administrators, Pro-style admin roles, and API tokens.

Permission names follow RustDesk Server Pro's admin roles (docs: Admin Role).
A permission check returns a Scope describing which users and devices it
covers, or raises 403.
"""

import json

from .web import HTTPError

# name -> (label, role types it is valid for)
PERMISSIONS = {
    "users.view": ("Users - View", ("global", "group")),
    "users.create": ("Users - Create", ("global", "group")),
    "users.invite": ("Users - Invite", ("global", "group")),
    "users.delete": ("Users - Delete", ("global", "group")),
    "users.enable_disable": ("Users - Enable/Disable", ("global", "group")),
    "users.edit_email": ("Users - Edit Email", ("global", "group")),
    "users.edit_password": ("Users - Edit Password", ("global", "group")),
    "users.edit_note": ("Users - Edit Note", ("global", "group")),
    "users.edit_display_name": ("Users - Edit Display Name", ("global", "group")),
    "users.manage_2fa": ("Users - Manage 2FA", ("global", "group")),
    "users.force_logout": ("Users - Force Logout", ("global", "group")),
    "users.change_group": ("Users - Update Group", ("global",)),
    "users.change_strategy": ("Users - Update Strategy", ("global", "group")),
    "devices.view": ("Devices - View", ("global", "individual", "group")),
    "devices.enable_disable": ("Devices - Enable/Disable", ("global", "individual", "group")),
    "devices.delete": ("Devices - Delete", ("global", "individual", "group")),
    "devices.edit_info": ("Devices - Edit Info", ("global", "individual", "group")),
    "devices.assign_to_user": ("Devices - Assign to User", ("global",)),
    "devices.change_group": ("Devices - Update Group", ("global",)),
    "devices.change_strategy": ("Devices - Update Strategy", ("global", "individual", "group")),
    "user_groups.view": ("User Groups - View", ("global",)),
    "user_groups.edit": ("User Groups - Edit", ("global",)),
    "device_groups.view": ("Device Groups - View", ("global",)),
    "device_groups.edit": ("Device Groups - Edit", ("global",)),
    "device_groups.change_strategy": ("Device Groups - Update Strategy", ("global",)),
    "audits.view": ("Audit Logs - View", ("global", "individual")),
    "audits.edit": ("Audit Logs - Edit (disconnect, notes)", ("global", "individual")),
    "strategies.view": ("Strategies - View", ("global",)),
    "strategies.edit": ("Strategies - Edit", ("global",)),
}

# Pro's API token permissions: resource -> level (0 none, 1 read, 2 read/write)
TOKEN_RESOURCES = {
    "device": "devices",
    "audit": "audits",
    "user": "users",
    "group": ("user_groups", "device_groups"),
    "strategy": "strategies",
    "ab": None,  # address books, checked separately
}


def implied(perm):
    """Permissions that grant `perm`: any edit permission includes view."""
    area, _, action = perm.partition(".")
    if action == "view":
        return {p for p in PERMISSIONS if p.startswith(area + ".")}
    if perm == "device_groups.change_strategy":
        return {perm, "device_groups.edit"}
    return {perm}


class Scope:
    """A set of users and devices a permission covers. `everything` wins."""

    def __init__(self, everything=False, user_groups=(), device_groups=(), unassigned=False,
                 own_user=None):
        self.everything = everything
        self.user_groups = set(user_groups)
        self.device_groups = set(device_groups)
        self.unassigned = unassigned
        self.own_users = {own_user} if own_user else set()

    def merge(self, other):
        self.everything = self.everything or other.everything
        self.user_groups |= other.user_groups
        self.device_groups |= other.device_groups
        self.unassigned = self.unassigned or other.unassigned
        self.own_users |= other.own_users

    def empty(self):
        return not (self.everything or self.user_groups or self.device_groups or self.unassigned
                    or self.own_users)

    def device_sql(self, alias="d"):
        if self.everything:
            return "1", ()
        parts, params = [], []
        if self.own_users:
            parts.append(f"{alias}.user_id IN ({','.join('?' * len(self.own_users))})")
            params += sorted(self.own_users)
        if self.user_groups:
            marks = ",".join("?" * len(self.user_groups))
            parts.append(f"{alias}.user_id IN (SELECT id FROM users WHERE group_id IN ({marks}))")
            params += sorted(self.user_groups)
        if self.device_groups:
            parts.append(f"{alias}.device_group_id IN ({','.join('?' * len(self.device_groups))})")
            params += sorted(self.device_groups)
        if self.unassigned:
            parts.append(f"({alias}.user_id IS NULL AND {alias}.device_group_id IS NULL)")
        return "(" + (" OR ".join(parts) or "0") + ")", tuple(params)

    def user_sql(self, alias="u"):
        """Users a group-scoped role may manage (never administrators)."""
        if self.everything:
            return "1", ()
        parts, params = [], []
        if self.user_groups:
            parts.append(f"{alias}.group_id IN ({','.join('?' * len(self.user_groups))})")
            params += sorted(self.user_groups)
        if self.own_users:
            parts.append(f"{alias}.id IN ({','.join('?' * len(self.own_users))})")
            params += sorted(self.own_users)
        return "(" + (" OR ".join(parts) or "0") + f") AND {alias}.is_admin = 0", tuple(params)


class Actor:
    """The caller of a console or REST request."""

    def __init__(self, user=None, token=None):
        self.user = user          # users row, or the token's creator
        self.token = token        # api_tokens row when authenticated by token
        self._roles = None

    @property
    def is_admin(self):
        return self.token is None and self.user is not None and bool(self.user["is_admin"])

    @property
    def name(self):
        if self.token is not None:
            return f"token:{self.token['name']}"
        return self.user["name"] if self.user else ""

    def roles(self, db):
        if self._roles is None:
            self._roles = [] if self.user is None or self.token is not None else db.all(
                "SELECT r.* FROM admin_roles r JOIN user_admin_roles ur ON ur.role_id = r.id "
                "WHERE ur.user_id = ?", (self.user["id"],))
        return self._roles

    def scope(self, db, perm):
        """The Scope `perm` covers for this actor (possibly empty)."""
        if self.is_admin:
            return Scope(everything=True)
        if self.token is not None:
            return self._token_scope(perm)
        wanted = implied(perm)
        scope = Scope()
        for role in self.roles(db):
            if not wanted & set(json.loads(role["perms"])):
                continue
            if role["type"] == "global":
                return Scope(everything=True)
            if role["type"] == "individual":
                scope.merge(Scope(own_user=self.user["id"]))
            else:
                scope.merge(Scope(user_groups=json.loads(role["user_groups"]),
                                  device_groups=json.loads(role["device_groups"]),
                                  unassigned=bool(role["unassigned"])))
        # Every user may look at their own devices and, unless restricted,
        # their own logs, as in Pro.
        if perm == "devices.view":
            scope.merge(Scope(own_user=self.user["id"]))
        if perm == "audits.view" and not db.setting("only_admin_logs"):
            scope.merge(Scope(own_user=self.user["id"]))
        return scope

    def _token_scope(self, perm):
        perms = json.loads(self.token["perms"] or "{}")
        area, _, action = perm.partition(".")
        for resource, areas in TOKEN_RESOURCES.items():
            areas = areas if isinstance(areas, tuple) else (areas,)
            if area in areas:
                level = perms.get(resource, 0)
                if level >= 2 or (level >= 1 and action == "view"):
                    return Scope(everything=True)
        return Scope()

    def require(self, db, perm):
        scope = self.scope(db, perm)
        if scope.empty():
            raise HTTPError(403, "You do not have permission for this")
        return scope

    def can(self, db, perm):
        return not self.scope(db, perm).empty()

    def ab_level(self):
        """Token permission on address books (0, 1 or 2)."""
        if self.token is None:
            return 0
        return json.loads(self.token["perms"] or "{}").get("ab", 0)

    def capabilities(self, db):
        """Which permissions this actor holds anywhere, for the console UI."""
        return sorted(p for p in PERMISSIONS if self.can(db, p))


def device_in_scope(db, scope, device_id):
    cond, params = scope.device_sql()
    return db.one(f"SELECT 1 FROM devices d WHERE d.id = ? AND {cond}", (device_id,) + params) is not None


def user_in_scope(db, scope, user_id):
    cond, params = scope.user_sql()
    return db.one(f"SELECT 1 FROM users u WHERE u.id = ? AND {cond}", (user_id,) + params) is not None
