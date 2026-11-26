pub const ROLES: &[&str] = &[
    "read_only",
    "boot_select",
    "recovery_access",
    "os_install",
    "storage_destructive",
    "admin",
];

pub fn known_role(role: &str) -> bool {
    ROLES.contains(&role)
}

pub fn is_admin(roles: &[String]) -> bool {
    roles.iter().any(|role| role == "admin")
}

pub fn has_role(roles: &[String], needed: &str) -> bool {
    if is_admin(roles) {
        return needed != "storage_destructive";
    }
    if needed == "read_only" {
        return roles.iter().any(|role| {
            matches!(
                role.as_str(),
                "read_only" | "boot_select" | "recovery_access" | "os_install"
            )
        });
    }
    roles.iter().any(|role| role == needed)
}

/// `grants` are the roles explicitly given on this device. The owner passes
/// `owner = true` and does not need a grant row.
pub fn device_allows(roles: &[String], owner: bool, grants: &[String], needed: &str) -> bool {
    if !has_role(roles, needed) {
        return false;
    }
    if is_admin(roles) || owner {
        return true;
    }
    if needed == "read_only" {
        return !grants.is_empty();
    }
    grants.iter().any(|grant| grant == needed)
}
