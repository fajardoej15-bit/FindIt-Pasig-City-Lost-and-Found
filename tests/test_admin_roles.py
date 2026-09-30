import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import database
from auth_controller import AuthController as RealAuthController


class AdminRoleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.database_env_patch = patch.dict(
            os.environ,
            {"DATABASE_URL": "", "SECRET_KEY": "role-test-secret"},
        )
        cls.database_env_patch.start()
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
            lambda: RealAuthController(),
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
        cls.database_env_patch.stop()

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

    def test_secret_key_requires_environment_value_outside_debug_mode(self):
        with patch.dict(os.environ, {"SECRET_KEY": "", "FLASK_DEBUG": "false"}):
            with self.assertRaisesRegex(RuntimeError, "SECRET_KEY must be set"):
                self.main.configured_secret_key()

        with patch.dict(
            os.environ,
            {
                "SECRET_KEY": "",
                "FLASK_DEBUG": "true",
                "DATABASE_URL": "postgresql://configured-by-test",
            },
        ):
            with self.assertRaisesRegex(RuntimeError, "SECRET_KEY must be set"):
                self.main.configured_secret_key()

    def test_secret_key_uses_environment_value_or_random_local_debug_value(self):
        with patch.dict(os.environ, {"SECRET_KEY": "configured-secret"}):
            self.assertEqual(self.main.configured_secret_key(), "configured-secret")

        with patch.dict(os.environ, {"SECRET_KEY": "", "FLASK_DEBUG": "true"}):
            first = self.main.configured_secret_key()
            second = self.main.configured_secret_key()

        self.assertEqual(len(first), 64)
        self.assertNotEqual(first, second)

    def test_public_pages_work_without_an_admin_session(self):
        for path in ("/", "/login", "/register"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 200)

    def test_existing_normal_user_can_log_in(self):
        response = self.client.post(
            "/login",
            data={"email": "user@example.test", "password": "test-password"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/dashboard")

    def test_registration_creates_pending_user_without_sql_error(self):
        email = f"new-{self.id().lower()}@example.test"
        with (
            patch.object(self.main, "AuthController", RealAuthController),
            patch.object(self.main, "issue_otp", return_value=True),
        ):
            response = self.client.post(
                "/register",
                data={
                    "full_name": "New User",
                    "email": email,
                    "password": "Password123",
                    "confirm_password": "Password123",
                    "security_question": "What is your favorite city?",
                    "security_answer": "Pasig",
                },
            )

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/verify-otp"))
        user = self.account(email)
        self.assertIsNotNone(user)
        self.assertEqual(user["role"], "user")
        self.assertEqual(user["account_status"], "PENDING")

    def test_registration_sends_gmail_otp_and_verification_activates_user(self):
        email = f"gmail-{self.id().lower()}@example.test"
        with (
            patch.object(self.main, "AuthController", RealAuthController),
            patch.dict(
                os.environ,
                {
                    "MAIL_USERNAME": "sender@gmail.com",
                    "MAIL_PASSWORD": "test-app-password",
                },
            ),
            patch.object(self.main.smtplib, "SMTP") as smtp_factory,
            patch.object(self.main.secrets, "randbelow", return_value=123456),
        ):
            response = self.client.post(
                "/register",
                data={
                    "full_name": "Resend Test",
                    "email": email,
                    "password": "Password123",
                    "confirm_password": "Password123",
                    "security_question": "What is your favorite city?",
                    "security_answer": "Pasig",
                },
            )

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/verify-otp"))
        smtp_factory.assert_called_once_with("smtp.gmail.com", 587, timeout=20)
        smtp = smtp_factory.return_value.__enter__.return_value
        smtp.starttls.assert_called_once_with()
        smtp.login.assert_called_once_with("sender@gmail.com", "test-app-password")
        message = smtp.send_message.call_args.args[0]
        self.assertEqual(
            message["From"],
            '"FindIt: Pasig City Lost & Found" <sender@gmail.com>',
        )
        self.assertEqual(message["To"], email)
        self.assertEqual(
            message["Subject"],
            "FindIt: Pasig City Lost & Found - Email Verification",
        )
        self.assertIn("123456", message.get_content())
        user = self.account(email)
        self.assertEqual(user["account_status"], "PENDING")
        conn = database.get_connection()
        challenge = conn.execute(
            "SELECT otp_hash FROM otp_verifications WHERE user_id=?",
            (user["id"],),
        ).fetchone()
        conn.close()
        self.assertEqual(challenge["otp_hash"], self.main.otp_hash("123456"))

        verification = self.client.post("/verify-otp", data={"otp": "123456"})
        self.assertEqual(verification.status_code, 302)
        self.assertEqual(verification.location, "/login")
        self.assertEqual(self.account(email)["account_status"], "ACTIVE")

    def test_incorrect_and_expired_registration_otp_do_not_activate_account(self):
        email = f"otp-check-{self.id().lower()}@example.test"
        conn = database.get_connection()
        conn.execute(
            "UPDATE users SET account_status='PENDING' WHERE id=?",
            (self.target_id,),
        )
        conn.execute(
            "INSERT INTO otp_verifications(user_id,otp_hash,expires_at,attempts,resend_count,last_sent_at) "
            "VALUES(?,?,?,?,?,?)",
            (
                self.target_id,
                self.main.otp_hash("123456"),
                (self.main.utc_now() + self.main.timedelta(minutes=10)).isoformat(),
                0,
                0,
                self.main.utc_now().isoformat(),
            ),
        )
        conn.execute(
            "UPDATE users SET email=? WHERE id=?",
            (email, self.target_id),
        )
        conn.commit()
        conn.close()
        with self.client.session_transaction() as session:
            session["pending_verification_user_id"] = self.target_id

        incorrect = self.client.post("/verify-otp", data={"otp": "654321"})
        self.assertEqual(incorrect.status_code, 200)
        self.assertIn(b"Invalid OTP", incorrect.data)
        self.assertEqual(self.account(email)["account_status"], "PENDING")

        conn = database.get_connection()
        conn.execute(
            "UPDATE otp_verifications SET expires_at=? WHERE user_id=?",
            (
                (self.main.utc_now() - self.main.timedelta(minutes=1)).isoformat(),
                self.target_id,
            ),
        )
        conn.commit()
        conn.close()
        expired = self.client.post("/verify-otp", data={"otp": "123456"})
        self.assertEqual(expired.status_code, 200)
        self.assertIn(b"OTP has expired", expired.data)
        self.assertEqual(self.account(email)["account_status"], "PENDING")

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
