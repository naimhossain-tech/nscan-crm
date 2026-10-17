import os
import re
import tempfile
import unittest

import app as crm
from werkzeug.security import generate_password_hash


class CRMTests(unittest.TestCase):
    def setUp(self):
        self.original_db = crm.DB
        handle = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.test_db = handle.name
        handle.close()

        crm.DB = self.test_db
        crm.app.config.update(
            TESTING=True,
            SECRET_KEY="test-secret-key-for-crm-only",
            SESSION_COOKIE_SECURE=False,
        )

        con = crm.db()
        con.close()
        self.client = crm.app.test_client()

    def tearDown(self):
        self.client = None
        crm.DB = self.original_db
        if os.path.exists(self.test_db):
            os.remove(self.test_db)

    def csrf_token(self, path):
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        match = re.search(
            r'<input[^>]*name="csrf_token"[^>]*value="([^"]+)"',
            html,
        )
        self.assertIsNotNone(match, f"CSRF token not found on {path}")
        return match.group(1)

    def create_admin(self):
        token = self.csrf_token("/setup")
        response = self.client.post(
            "/setup",
            data={
                "username": "admin",
                "password": "StrongPassword123!",
                "confirm": "StrongPassword123!",
                "csrf_token": token,
            },
        )
        self.assertEqual(response.status_code, 302)

    def login(self, username="admin", password="StrongPassword123!"):
        token = self.csrf_token("/login")
        return self.client.post(
            "/login",
            data={
                "username": username,
                "password": password,
                "csrf_token": token,
            },
        )

    def test_setup_creates_admin_and_login_works(self):
        self.create_admin()
        response = self.login()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/")

    def test_wrong_password_does_not_log_in(self):
        self.create_admin()
        response = self.login(password="WrongPassword123!")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("user_id", self.client.get(
            "/login"
        ).request.environ.get("unused", {}))

    def test_dashboard_requires_login(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.location)

    def test_admin_can_add_customer(self):
        self.create_admin()
        self.login()

        token = self.csrf_token("/crm/add")
        response = self.client.post(
            "/crm/add",
            data={
                "name": "Test Customer",
                "phone": "01700000000",
                "email": "customer@example.com",
                "company": "Test Company",
                "notes": "Automated test",
                "csrf_token": token,
            },
        )
        self.assertEqual(response.status_code, 302)

        con = crm.db()
        customer = con.execute(
            "SELECT * FROM customers WHERE name = ?",
            ("Test Customer",),
        ).fetchone()
        con.close()

        self.assertIsNotNone(customer)
        self.assertEqual(customer["phone"], "01700000000")

    def test_agent_cannot_open_admin_users_page(self):
        self.create_admin()

        con = crm.db()
        con.execute(
            "INSERT INTO users(username, password_hash, role) "
            "VALUES (?, ?, ?)",
            (
                "agent1",
                generate_password_hash("AgentPassword123!"),
                "agent",
            ),
        )
        con.commit()
        con.close()

        agent_client = crm.app.test_client()
        token_response = agent_client.get("/login")
        self.assertEqual(token_response.status_code, 200)

        html = token_response.get_data(as_text=True)
        match = re.search(
            r'<input[^>]*name="csrf_token"[^>]*value="([^"]+)"',
            html,
        )
        self.assertIsNotNone(match, "Login CSRF token not found")

        response = agent_client.post(
            "/login",
            data={
                "username": "agent1",
                "password": "AgentPassword123!",
                "csrf_token": match.group(1),
            },
        )
        self.assertEqual(response.status_code, 302)

        response = agent_client.get("/admin/users")
        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main(verbosity=2)
