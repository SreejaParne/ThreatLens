class RBACEngine:
    def __init__(self):
        self.permissions = {
            "admin": {
                "view_dashboard",
                "trigger_response",
                "block_ip",
                "view_reports",
                "export_reports",
                "manage_users"
            },
            "analyst": {
                "view_dashboard",
                "trigger_response",
                "view_reports",
                "export_reports"
            },
            "viewer": {
                "view_dashboard",
                "view_reports"
            }
        }

    def has_permission(self, role, action):
        return action in self.permissions.get(role, set())