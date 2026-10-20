//! Who may do what: administrators, Pro-style admin roles, and API tokens.
//! Port of authz.py. A permission check returns a Scope describing which users
//! and devices it covers, or a 403.

use std::collections::BTreeSet;

use crate::db::{Database, SqlValue};
use crate::web::{HttpError, HttpResult};

/// (name, label, role types it is valid for). Follows Pro's admin roles.
pub const PERMISSIONS: &[(&str, &str, &[&str])] = &[
    ("users.view", "Users - View", &["global", "group"]),
    ("users.create", "Users - Create", &["global", "group"]),
    ("users.invite", "Users - Invite", &["global", "group"]),
    ("users.delete", "Users - Delete", &["global", "group"]),
    ("users.enable_disable", "Users - Enable/Disable", &["global", "group"]),
    ("users.edit_email", "Users - Edit Email", &["global", "group"]),
    ("users.edit_password", "Users - Edit Password", &["global", "group"]),
    ("users.edit_note", "Users - Edit Note", &["global", "group"]),
    ("users.edit_display_name", "Users - Edit Display Name", &["global", "group"]),
    ("users.manage_2fa", "Users - Manage 2FA", &["global", "group"]),
    ("users.force_logout", "Users - Force Logout", &["global", "group"]),
    ("users.change_group", "Users - Update Group", &["global"]),
    ("users.change_strategy", "Users - Update Strategy", &["global", "group"]),
    ("devices.view", "Devices - View", &["global", "individual", "group"]),
    ("devices.enable_disable", "Devices - Enable/Disable", &["global", "individual", "group"]),
    ("devices.delete", "Devices - Delete", &["global", "individual", "group"]),
    ("devices.edit_info", "Devices - Edit Info", &["global", "individual", "group"]),
    ("devices.assign_to_user", "Devices - Assign to User", &["global"]),
    ("devices.change_group", "Devices - Update Group", &["global"]),
    ("devices.change_strategy", "Devices - Update Strategy", &["global", "individual", "group"]),
    ("user_groups.view", "User Groups - View", &["global"]),
    ("user_groups.edit", "User Groups - Edit", &["global"]),
    ("device_groups.view", "Device Groups - View", &["global"]),
    ("device_groups.edit", "Device Groups - Edit", &["global"]),
    ("device_groups.change_strategy", "Device Groups - Update Strategy", &["global"]),
    ("audits.view", "Audit Logs - View", &["global", "individual"]),
    ("audits.edit", "Audit Logs - Edit (disconnect, notes)", &["global", "individual"]),
    ("strategies.view", "Strategies - View", &["global"]),
    ("strategies.edit", "Strategies - Edit", &["global"]),
];

/// Pro's API token permissions: resource -> permission area(s).
fn token_resource_areas(resource: &str) -> &'static [&'static str] {
    match resource {
        "device" => &["devices"],
        "audit" => &["audits"],
        "user" => &["users"],
        "group" => &["user_groups", "device_groups"],
        "strategy" => &["strategies"],
        _ => &[],
    }
}

/// Permissions that grant `perm`: any edit permission includes view.
pub fn implied(perm: &str) -> BTreeSet<String> {
    let (area, action) = perm.split_once('.').unwrap_or((perm, ""));
    if action == "view" {
        let prefix = format!("{area}.");
        return PERMISSIONS
            .iter()
            .map(|(n, _, _)| n.to_string())
            .filter(|n| n.starts_with(&prefix))
            .collect();
    }
    if perm == "device_groups.change_strategy" {
        return ["device_groups.change_strategy", "device_groups.edit"]
            .iter()
            .map(|s| s.to_string())
            .collect();
    }
    std::iter::once(perm.to_string()).collect()
}

/// A set of users and devices a permission covers. `everything` wins.
#[derive(Default, Clone)]
pub struct Scope {
    pub everything: bool,
    pub user_groups: BTreeSet<i64>,
    pub device_groups: BTreeSet<i64>,
    pub unassigned: bool,
    pub own_users: BTreeSet<i64>,
}

impl Scope {
    pub fn everything() -> Self {
        Scope {
            everything: true,
            ..Default::default()
        }
    }

    pub fn own_user(id: i64) -> Self {
        let mut s = Scope::default();
        s.own_users.insert(id);
        s
    }

    pub fn merge(&mut self, other: &Scope) {
        self.everything |= other.everything;
        self.user_groups.extend(&other.user_groups);
        self.device_groups.extend(&other.device_groups);
        self.unassigned |= other.unassigned;
        self.own_users.extend(&other.own_users);
    }

    pub fn empty(&self) -> bool {
        !(self.everything
            || !self.user_groups.is_empty()
            || !self.device_groups.is_empty()
            || self.unassigned
            || !self.own_users.is_empty())
    }

    fn marks(n: usize) -> String {
        std::iter::repeat("?").take(n).collect::<Vec<_>>().join(",")
    }

    /// SQL condition + params for devices in scope (alias default "d").
    pub fn device_sql(&self, alias: &str) -> (String, Vec<i64>) {
        if self.everything {
            return ("1".to_string(), vec![]);
        }
        let mut parts = Vec::new();
        let mut params = Vec::new();
        if !self.own_users.is_empty() {
            parts.push(format!(
                "{alias}.user_id IN ({})",
                Self::marks(self.own_users.len())
            ));
            params.extend(self.own_users.iter().copied());
        }
        if !self.user_groups.is_empty() {
            parts.push(format!(
                "{alias}.user_id IN (SELECT id FROM users WHERE group_id IN ({}))",
                Self::marks(self.user_groups.len())
            ));
            params.extend(self.user_groups.iter().copied());
        }
        if !self.device_groups.is_empty() {
            parts.push(format!(
                "{alias}.device_group_id IN ({})",
                Self::marks(self.device_groups.len())
            ));
            params.extend(self.device_groups.iter().copied());
        }
        if self.unassigned {
            parts.push(format!(
                "({alias}.user_id IS NULL AND {alias}.device_group_id IS NULL)"
            ));
        }
        let cond = if parts.is_empty() {
            "0".to_string()
        } else {
            parts.join(" OR ")
        };
        (format!("({cond})"), params)
    }

    /// Users a group-scoped role may manage (never administrators).
    pub fn user_sql(&self, alias: &str) -> (String, Vec<i64>) {
        if self.everything {
            return ("1".to_string(), vec![]);
        }
        let mut parts = Vec::new();
        let mut params = Vec::new();
        if !self.user_groups.is_empty() {
            parts.push(format!(
                "{alias}.group_id IN ({})",
                Self::marks(self.user_groups.len())
            ));
            params.extend(self.user_groups.iter().copied());
        }
        if !self.own_users.is_empty() {
            parts.push(format!(
                "{alias}.id IN ({})",
                Self::marks(self.own_users.len())
            ));
            params.extend(self.own_users.iter().copied());
        }
        let cond = if parts.is_empty() {
            "0".to_string()
        } else {
            parts.join(" OR ")
        };
        (format!("({cond}) AND {alias}.is_admin = 0"), params)
    }
}

/// The caller of a console or REST request.
pub struct Actor {
    pub user_id: Option<i64>,
    pub group_id: Option<i64>,
    pub user_is_admin: bool,
    pub user_name: String,
    /// Set when authenticated by an API token: its name and perms JSON.
    pub token_name: Option<String>,
    pub token_perms: Option<String>,
}

impl Actor {
    pub fn is_admin(&self) -> bool {
        self.token_name.is_none() && self.user_is_admin
    }

    pub fn name(&self) -> String {
        if let Some(n) = &self.token_name {
            format!("token:{n}")
        } else {
            self.user_name.clone()
        }
    }

    fn roles(&self, db: &Database) -> Vec<RoleRow> {
        if self.token_name.is_some() {
            return vec![];
        }
        let Some(uid) = self.user_id else {
            return vec![];
        };
        let rows = db
            .query(
                "SELECT r.type, r.perms, r.user_groups, r.device_groups, r.unassigned \
                 FROM admin_roles r JOIN user_admin_roles ur ON ur.role_id = r.id \
                 WHERE ur.user_id = ?1",
                &[SqlValue::Int(uid)],
            )
            .unwrap_or_default();
        let field = |r: &crate::db::Row, k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        rows.iter()
            .map(|r| RoleRow {
                rtype: field(r, "type"),
                perms: field(r, "perms"),
                user_groups: field(r, "user_groups"),
                device_groups: field(r, "device_groups"),
                unassigned: r.get("unassigned").and_then(|v| v.as_i64()).unwrap_or(0) != 0,
            })
            .collect()
    }

    /// The Scope `perm` covers for this actor (possibly empty).
    pub fn scope(&self, db: &Database, perm: &str) -> Scope {
        if self.is_admin() {
            return Scope::everything();
        }
        if self.token_name.is_some() {
            return self.token_scope(perm);
        }
        let wanted = implied(perm);
        let mut scope = Scope::default();
        for role in self.roles(db) {
            let have: BTreeSet<String> = json_str_set(&role.perms);
            if wanted.is_disjoint(&have) {
                continue;
            }
            match role.rtype.as_str() {
                "global" => return Scope::everything(),
                "individual" => {
                    if let Some(uid) = self.user_id {
                        scope.merge(&Scope::own_user(uid));
                    }
                }
                _ => {
                    let mut s = Scope::default();
                    s.user_groups = json_int_set(&role.user_groups);
                    s.device_groups = json_int_set(&role.device_groups);
                    s.unassigned = role.unassigned;
                    scope.merge(&s);
                }
            }
        }
        if perm == "devices.view" {
            if let Some(uid) = self.user_id {
                scope.merge(&Scope::own_user(uid));
            }
        }
        if perm == "audits.view" && !db.settings().only_admin_logs {
            if let Some(uid) = self.user_id {
                scope.merge(&Scope::own_user(uid));
            }
        }
        scope
    }

    fn token_scope(&self, perm: &str) -> Scope {
        let perms: crate::json::Value = self
            .token_perms
            .as_deref()
            .and_then(|s| crate::json::from_str(s).ok())
            .unwrap_or(json!({}));
        let (area, action) = perm.split_once('.').unwrap_or((perm, ""));
        for resource in ["device", "audit", "user", "group", "strategy"] {
            if token_resource_areas(resource).contains(&area) {
                let level = perms.get(resource).and_then(|v| v.as_i64()).unwrap_or(0);
                if level >= 2 || (level >= 1 && action == "view") {
                    return Scope::everything();
                }
            }
        }
        Scope::default()
    }

    pub fn require(&self, db: &Database, perm: &str) -> HttpResult<Scope> {
        let scope = self.scope(db, perm);
        if scope.empty() {
            return Err(HttpError::new(403, "You do not have permission for this"));
        }
        Ok(scope)
    }

    pub fn can(&self, db: &Database, perm: &str) -> bool {
        !self.scope(db, perm).empty()
    }

    /// Token permission on address books (0, 1 or 2).
    pub fn ab_level(&self) -> i64 {
        let Some(perms) = &self.token_perms else {
            return 0;
        };
        crate::json::from_str(perms)
            .ok()
            .and_then(|v| v.get("ab").and_then(|x| x.as_i64()))
            .unwrap_or(0)
    }

    /// Which permissions this actor holds anywhere, for the console UI.
    pub fn capabilities(&self, db: &Database) -> Vec<String> {
        let mut caps: Vec<String> = PERMISSIONS
            .iter()
            .map(|(n, _, _)| n.to_string())
            .filter(|p| self.can(db, p))
            .collect();
        caps.sort();
        caps
    }
}

struct RoleRow {
    rtype: String,
    perms: String,
    user_groups: String,
    device_groups: String,
    unassigned: bool,
}

fn json_int_set(s: &str) -> BTreeSet<i64> {
    match crate::json::from_str(s) {
        Ok(crate::json::Value::Array(a)) => a.iter().filter_map(|v| v.as_i64()).collect(),
        _ => BTreeSet::new(),
    }
}

fn json_str_set(s: &str) -> BTreeSet<String> {
    match crate::json::from_str(s) {
        Ok(crate::json::Value::Array(a)) => {
            a.iter().filter_map(|v| v.as_str().map(|x| x.to_string())).collect()
        }
        _ => BTreeSet::new(),
    }
}

pub fn device_in_scope(db: &Database, scope: &Scope, device_id: &str) -> bool {
    let (cond, params) = scope.device_sql("d");
    let mut args: Vec<SqlValue> = vec![SqlValue::Text(device_id.to_string())];
    args.extend(params.into_iter().map(SqlValue::Int));
    db.query_one(&format!("SELECT 1 AS n FROM devices d WHERE d.id = ? AND {cond}"), &args)
        .ok()
        .flatten()
        .is_some()
}

pub fn user_in_scope(db: &Database, scope: &Scope, user_id: i64) -> bool {
    let (cond, params) = scope.user_sql("u");
    let mut args: Vec<SqlValue> = vec![SqlValue::Int(user_id)];
    args.extend(params.into_iter().map(SqlValue::Int));
    db.query_one(&format!("SELECT 1 AS n FROM users u WHERE u.id = ? AND {cond}"), &args)
        .ok()
        .flatten()
        .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn implied_view_covers_area() {
        let imp = implied("users.view");
        assert!(imp.contains("users.view"));
        assert!(imp.contains("users.create"));
        assert!(imp.contains("users.delete"));
        assert!(!imp.contains("devices.view"));
    }

    #[test]
    fn implied_edit_is_itself() {
        let imp = implied("users.delete");
        assert_eq!(imp.len(), 1);
        assert!(imp.contains("users.delete"));
        let imp2 = implied("device_groups.change_strategy");
        assert!(imp2.contains("device_groups.edit"));
    }

    #[test]
    fn admin_scope_is_everything() {
        let actor = Actor {
            user_id: Some(1),
            group_id: None,
            user_is_admin: true,
            user_name: "admin".into(),
            token_name: None,
            token_perms: None,
        };
        assert!(actor.is_admin());
        let (cond, params) = Scope::everything().device_sql("d");
        assert_eq!(cond, "1");
        assert!(params.is_empty());
    }

    #[test]
    fn scope_device_sql_builds_params() {
        let mut s = Scope::default();
        s.own_users.insert(7);
        s.device_groups.insert(3);
        let (cond, params) = s.device_sql("d");
        assert!(cond.contains("d.user_id IN (?)"));
        assert!(cond.contains("d.device_group_id IN (?)"));
        assert_eq!(params, vec![7, 3]);
        assert!(!s.empty());
    }

    #[test]
    fn empty_scope() {
        assert!(Scope::default().empty());
    }

    #[test]
    fn token_name_prefixes() {
        let actor = Actor {
            user_id: Some(2),
            group_id: None,
            user_is_admin: true, // ignored because token present
            user_name: "bob".into(),
            token_name: Some("ci".into()),
            token_perms: Some("{\"device\":2}".into()),
        };
        assert!(!actor.is_admin());
        assert_eq!(actor.name(), "token:ci");
        assert!(actor.token_scope("devices.view").everything);
        assert!(actor.token_scope("devices.delete").everything);
        assert!(!actor.token_scope("users.view").everything);
        assert_eq!(actor.ab_level(), 0);
    }
}
