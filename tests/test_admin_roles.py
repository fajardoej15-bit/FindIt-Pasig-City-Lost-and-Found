import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import database
from auth_controller import AuthController as RealAuthController


class AdminRoleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original_db_name = database.DB_NAME
        cls.temp_dir = tempfile.TemporaryDirectory()
        database.DB_NAME = str(Path(cls.temp_dir.name) / "roles-test.db")
        conn = sqlite3.connect(database.DB_NAME)
        conn.execute(
            "CREATE TABLE users ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, "
            "email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, "
            "role TEXT NOT NULL DEFAULT 'user', full_name TEXT, student_id TEXT)"
        )
        conn.execute(
            "INSERT INTO users(username,email,password_hash,role,full_name) "
            "VALUES(?,?,?,?,?)",
            ("legacy-admin", "main@example.test", "unused", "ADMIN", "Main"),
        )
        conn.execute(
            "INSERT INTO users(username,email,password_hash,role,full_name) "
            "VALUES(?,?,?,?,?)",
            ("regular-user", "user@example.test", "unused", "USER", "User"),
        )
        conn.commit()
        conn.close()

        import main

        cls.main = main
        cls.auth_patch = patch.object(
            main,
            "AuthController",
            lambda _path: RealAuthController(database.DB_NAME),
        )
        cls.auth_patch.start()
        main.app.config.update(TESTING=True, SECRET_KEY="role-test-secret")

        conn = database.get_connection()
        conn.execute(
            "UPDATE users SET password_hash=? WHERE email=?",
            (RealAuthController.password_hash("test-password"), "main@example.test"),
        )
        conn.execute(
            "UPDATE users SET password_hash=? WHERE email=?",
            (RealAuthController.password_hash("test-password"), "user@example.test"),
        )
        conn.execute(
            "INSERT INTO users(username,email,password_hash,role,full_name,account_status,created_at,admin_level,admin_permissions) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (
                "full-admin",
                "full@example.test",
                RealAuthController.password_hash("test-password"),
                "admin",
                "Full",
                "ACTIVE",
                "2026-01-01",
                "FULL_ADMIN",
                "{}",
            ),
        )
        conn.execute(
            "INSERT INTO users(username,email,password_hash,role,full_name,account_status,created_at,admin_level,admin_permissions) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (
                "restricted-admin",
                "restricted@example.test",
                RealAuthController.password_hash("test-password"),
                "admin",
                "Restricted",
                "ACTIVE",
                "2026-01-02",
                "RESTRICTED_ADMIN",
                "{}",
            ),
        )
        conn.commit()
        conn.close()

    @classmethod
    def tearDownClass(cls):
        cls.auth_patch.stop()
        database.DB_NAME = cls.original_db_name
        cls.temp_dir.cleanup()

    def setUp(self):
        self.client = self.main.app.test_client()
        conn = database.get_connection()
        conn.execute(
            "UPDATE users SET role='admin',admin_level='MAIN_ADMIN',admin_permissions='{}' "
            "WHERE email='main@example.test'"
        )
        conn.execute(
            "UPDATE users SET role='admin',admin_level='FULL_ADMIN',admin_permissions='{}' "
            "WHERE email='full@example.test'"
        )
        conn.execute(
            "UPDATE users SET role='admin',admin_level='RESTRICTED_ADMIN',admin_permissions='{}' "
            "WHERE email='restricted@example.test'"
        )
        conn.execute(
            "UPDATE users SET role='user',admin_level=NULL,admin_permissions='{}' "
            "WHERE email='user@example.test' OR username LIKE 'target-%'"
        )
        conn.execute(
            "UPDATE users SET admin_permissions='{}' WHERE email='full@example.test'"
        )
        conn.execute(
            "INSERT INTO users(username,email,password_hash,role,full_name,account_status,created_at,admin_level,admin_permissions) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (
                f"target-{self.id()}",
                f"{self.id()}@example.test",
                RealAuthController.password_hash("test-password"),
                "user",
                "Target",
                "ACTIVE",
                "2026-01-03",
                None,
                "{}",
            ),
        )
        self.target_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.commit()
        conn.close()

    def login(self, email):
        response = self.client.post(
            "/login",
            data={"email": email, "password": "test-password"},
        )
        self.assertEqual(response.status_code, 302)

    def role_post(self, user_id, role, **permissions):
        self.client.get(f"/admin/users/{user_id}")
        with self.client.session_transaction() as session:
            csrf_token = session["admin_csrf_token"]
        data = {"csrf_token": csrf_token, "role": role}
        data.update(
            {
                permission: "on"
                for permission, enabled in permissions.items()
                if enabled
            }
        )
        return self.client.post(f"/admin/users/{user_id}/role", data=data)

    def account(self, email):
        conn = database.get_connection()
        user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        conn.close()
        return user

    def test_migration_preserves_the_single_legacy_admin_as_main_admin(self):
        self.assertEqual(self.account("main@example.test")["admin_level"], "MAIN_ADMIN")
        self.assertEqual(self.account("user@example.test")["role"], "user")
        conn = database.get_connection()
        seeded_admin = conn.execute(
            "SELECT id FROM users WHERE username='admin' OR email='admin@example.com'"
        ).fetchone()
        conn.close()
        self.assertIsNone(seeded_admin)

    def test_admin_dashboard_and_user_pages_render_hierarchical_role_names(self):
        self.login("main@example.test")
        self.assertEqual(self.client.get("/admin").status_code, 200)
        user_list = self.client.get("/admin/users")
        self.assertEqual(user_list.status_code, 200)
        self.assertIn(b"Main Admin", user_list.data)
        main_user = self.account("main@example.test")
        detail = self.client.get(f"/admin/users/{main_user['id']}")
        self.assertEqual(detail.status_code, 200)
        self.assertIn(b"Main Admin", detail.data)

    def test_homepage_uses_findit_branding(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"FindIt: Pasig City Lost &amp; Found", response.data)
        self.assertNotIn(b"SMART LOST &amp; FOUND", response.data)

    def test_main_admin_can_assign_roles_and_the_change_is_audited(self):
        self.login("main@example.test")
        response = self.role_post(
            self.target_id,
            "FULL_ADMIN",
            promote_users=True,
            delete_users=True,
        )
        self.assertEqual(response.status_code, 302)

        target = self.account(f"{self.id()}@example.test")
        self.assertEqual(target["role"], "admin")
        self.assertEqual(target["admin_level"], "FULL_ADMIN")
        self.assertEqual(
            json.loads(target["admin_permissions"]),
            {"delete_users": True, "promote_users": True},
        )
        conn = database.get_connection()
        audit = conn.execute(
            "SELECT user_id,action,details FROM audit_logs "
            "WHERE action='ADMIN_ROLE_CHANGED' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        conn.close()
        self.assertEqual(audit["user_id"], self.account("main@example.test")["id"])
        self.assertIn("from User to Full Admin", audit["details"])
        self.assertIn(str(self.target_id), audit["details"])

    def test_main_admin_can_assign_and_revoke_main_admin_privileges(self):
        self.login("main@example.test")
        self.assertEqual(
            self.role_post(self.target_id, "MAIN_ADMIN").status_code,
            302,
        )

        self.client = self.main.app.test_client()
        self.login(f"{self.id()}@example.test")
        original_main_id = self.account("main@example.test")["id"]
        self.assertEqual(
            self.role_post(original_main_id, "USER").status_code,
            302,
        )
        self.assertEqual(self.account("main@example.test")["role"], "user")
        self.assertEqual(
            self.account(f"{self.id()}@example.test")["admin_level"],
            "MAIN_ADMIN",
        )

    def test_full_admin_can_only_promote_to_restricted_admin_with_permission(self):
        conn = database.get_connection()
        conn.execute(
            "UPDATE users SET admin_permissions=? WHERE email='full@example.test'",
            (json.dumps({"promote_users": True}),),
        )
        conn.commit()
        conn.close()

        self.login("full@example.test")
        response = self.role_post(self.target_id, "RESTRICTED_ADMIN")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            self.account(f"{self.id()}@example.test")["admin_level"],
            "RESTRICTED_ADMIN",
        )

    def test_full_admin_without_promotion_permission_sees_no_promote_action(self):
        self.login("full@example.test")
        page = self.client.get(f"/admin/users/{self.target_id}")
        self.assertEqual(page.status_code, 200)
        self.assertNotIn(b"Promote to Restricted Admin", page.data)
        response = self.role_post(self.target_id, "RESTRICTED_ADMIN")
        self.assertEqual(response.status_code, 403)
        self.assertIsNone(self.account(f"{self.id()}@example.test")["admin_level"])

    def test_full_admin_cannot_escalate_roles_or_modify_main_admin(self):
        conn = database.get_connection()
        conn.execute(
            "UPDATE users SET admin_permissions=? WHERE email='full@example.test'",
            (json.dumps({"promote_users": True, "delete_users": True}),),
        )
        conn.commit()
        conn.close()

        self.login("full@example.test")
        self.assertEqual(
            self.role_post(self.target_id, "FULL_ADMIN").status_code,
            403,
        )
        main_id = self.account("main@example.test")["id"]
        self.assertEqual(self.role_post(main_id, "USER").status_code, 403)
        self.assertEqual(
            self.role_post(self.account("full@example.test")["id"], "MAIN_ADMIN").status_code,
            403,
        )
        self.assertEqual(self.client.post(
            f"/admin/users/{main_id}/delete",
            data={"csrf_token": "irrelevant"},
        ).status_code, 403)
        self.assertEqual(self.account("main@example.test")["admin_level"], "MAIN_ADMIN")
        self.assertEqual(
            self.account(f"{self.id()}@example.test")["admin_level"],
            None,
        )

    def test_restricted_admin_and_normal_user_cannot_manage_roles(self):
        self.login("restricted@example.test")
        user_list = self.client.get("/admin/users")
        self.assertEqual(user_list.status_code, 200)
        user_detail = self.client.get(f"/admin/users/{self.target_id}")
        self.assertEqual(user_detail.status_code, 200)
        self.assertNotIn(b"Promote to Restricted Admin", user_detail.data)
        with self.client.session_transaction() as session:
            session["admin_csrf_token"] = "valid-token"
        response = self.client.post(
            f"/admin/users/{self.target_id}/role",
            data={"csrf_token": "valid-token", "role": "RESTRICTED_ADMIN"},
        )
        self.assertEqual(response.status_code, 403)

        self.client = self.main.app.test_client()
        self.login("user@example.test")
        self.assertEqual(self.client.get("/admin").status_code, 403)
        self.assertEqual(self.client.get("/admin/users").status_code, 403)
        self.assertEqual(
            self.client.post(
                f"/admin/users/{self.target_id}/role",
                data={"role": "MAIN_ADMIN"},
            ).status_code,
            403,
        )

    def test_role_change_requires_a_valid_csrf_token(self):
        self.login("main@example.test")
        response = self.client.post(
            f"/admin/users/{self.target_id}/role",
            data={"role": "RESTRICTED_ADMIN", "csrf_token": "invalid"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertIsNone(self.account(f"{self.id()}@example.test")["admin_level"])


if __name__ == "__main__":
    unittest.main()
