# API tests for Services 1-3 using Flask's test client on a throwaway database
# Maya Zeaiter
# Run from the project folder:  python -m unittest discover tests -v
import os
import sys
import tempfile
import unittest

TMP_DB = os.path.join(tempfile.mkdtemp(), "test.db")
os.environ["SECURITY_DB_PATH"] = TMP_DB
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import seed  # noqa: E402
from app import app  # noqa: E402
from database import connect_to_db  # noqa: E402


class ApiTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        seed.seed()
        cls.client = app.test_client()
        cls.tokens = {name: cls.login(name, pw) for name, pw in [
            ("admin_maya", "Admin@1234"), ("analyst_karim", "Analyst@1234"), ("analyst_lina", "Analyst@1234"),
            ("user_rami", "User@1234"), ("auditor_sara", "Auditor@1234")]}

    @classmethod
    def login(cls, username, password):
        r = cls.client.post("/users/login", json={"username": username, "password": password})
        assert r.status_code == 200, r.get_json()
        return r.get_json()["data"]["token"]

    def call(self, method, url, who=None, **kwargs):
        headers = {"Authorization": f"Bearer {self.tokens[who]}"} if who else {}
        return getattr(self.client, method)(url, headers=headers, **kwargs)


class UsersTests(ApiTestCase):
    def test_register_and_duplicate(self):
        body = {"full_name": "New Person", "username": "new_person", "email": "new@company.com",
                "password": "Strong@123", "department": "Ops", "role": "Regular User"}
        r = self.call("post", "/users/register", json=body)
        self.assertEqual(r.status_code, 201)
        self.assertNotIn("password_hash", r.get_json()["data"])
        self.assertEqual(r.get_json()["developer"], "Maya Zeaiter")
        stored = connect_to_db().execute("SELECT password_hash FROM users WHERE username='new_person'").fetchone()
        self.assertNotEqual(stored[0], "Strong@123")
        self.assertEqual(self.call("post", "/users/register", json=body).status_code, 409)

    def test_register_validation(self):
        r = self.call("post", "/users/register", json={"full_name": "X", "username": "x!", "email": "bad",
                                                      "password": "weak", "department": "D", "role": "Hacker"})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(set(r.get_json()["errors"]), {"username", "email", "password", "role"})
        self.assertEqual(self.call("post", "/users/register", json={}).status_code, 400)

    def test_privileged_role_needs_admin(self):
        body = {"full_name": "Sneaky", "username": "sneaky", "email": "sneaky@company.com",
                "password": "Strong@123", "department": "D", "role": "Security Administrator"}
        self.assertEqual(self.call("post", "/users/register", json=body).status_code, 403)
        self.assertEqual(self.call("post", "/users/register", "admin_maya", json=body).status_code, 201)

    def test_login_failures(self):
        self.assertEqual(self.client.post("/users/login", json={"username": "admin_maya",
                                                                "password": "wrong"}).status_code, 401)
        self.assertEqual(self.client.post("/users/login", json={"username": "user_suspended",
                                                                "password": "User@1234"}).status_code, 403)
        self.assertEqual(self.client.get("/users").status_code, 401)

    def test_update_permissions(self):
        self.assertEqual(self.call("put", "/users/4", "user_rami", json={"department": "Accounting"}).status_code, 200)
        self.assertEqual(self.call("put", "/users/2", "user_rami", json={"department": "X"}).status_code, 403)
        self.assertEqual(self.call("put", "/users/4", "user_rami", json={"role": "Auditor"}).status_code, 400)
        r = self.call("put", "/users/4", "admin_maya", json={"email": "rami.n@company.com"})
        self.assertEqual(r.get_json()["data"]["after"]["email"], "rami.n@company.com")

    def test_get_users(self):
        self.assertEqual(self.call("get", "/users", "auditor_sara").status_code, 200)
        self.assertEqual(self.call("get", "/users", "analyst_karim").status_code, 403)
        self.assertEqual(self.call("get", "/users/admin_maya", "admin_maya").status_code, 200)
        self.assertEqual(self.call("get", "/users/ghost", "admin_maya").status_code, 404)
        self.assertEqual(self.call("get", "/users/user_rami", "user_rami").status_code, 200)
        self.assertEqual(self.call("get", "/users/admin_maya", "user_rami").status_code, 403)

    def test_delete_user(self):
        body = {"full_name": "Temp", "username": "temp_user", "email": "temp@company.com",
                "password": "Strong@123", "department": "D", "role": "Regular User"}
        uid = self.call("post", "/users/register", json=body).get_json()["data"]["user_id"]
        self.assertEqual(self.call("delete", f"/users/{uid}", "auditor_sara").status_code, 403)
        self.assertEqual(self.call("delete", f"/users/{uid}", "admin_maya").status_code, 200)
        self.assertEqual(self.call("delete", f"/users/{uid}", "admin_maya").status_code, 404)
        logs = connect_to_db().execute("SELECT action_performed FROM logs").fetchall()
        actions = {row[0] for row in logs}
        self.assertTrue({"USER_DELETED", "UNAUTHORIZED_ACCESS", "LOGIN_SUCCESS"} <= actions)


class AssetsTests(ApiTestCase):
    asset = {"asset_name": "Test VM", "asset_type": "Server", "ip_address": "192.168.1.50",
             "department": "IT", "owner_id": 1, "criticality_level": "High"}

    def test_create_validate_update_delete(self):
        bad = dict(self.asset, ip_address="999.1.1.1", asset_type="Toaster", criticality_level="Extreme")
        r = self.call("post", "/assets", "admin_maya", json=bad)
        self.assertEqual(set(r.get_json()["errors"]), {"ip_address", "asset_type", "criticality_level"})
        self.assertEqual(self.call("post", "/assets", "analyst_karim", json=self.asset).status_code, 403)
        r = self.call("post", "/assets", "admin_maya", json=self.asset)
        self.assertEqual(r.status_code, 201)
        aid = r.get_json()["data"]["asset_id"]
        r = self.call("put", f"/assets/{aid}", "admin_maya", json={"status": "Under Maintenance"})
        self.assertEqual(r.get_json()["data"]["before"]["status"], "Active")
        self.assertEqual(r.get_json()["data"]["after"]["status"], "Under Maintenance")
        self.assertEqual(self.call("delete", f"/assets/{aid}", "analyst_karim").status_code, 403)
        self.assertEqual(self.call("delete", f"/assets/{aid}", "admin_maya").status_code, 200)

    def test_read_and_search(self):
        self.assertEqual(self.call("get", "/assets", "auditor_sara").status_code, 200)
        self.assertEqual(self.call("get", "/assets", "analyst_karim").status_code, 403)
        self.assertEqual(self.call("get", "/assets", "user_rami").status_code, 403)
        r = self.call("get", "/assets/1", "analyst_karim")
        self.assertIn("related_incidents", r.get_json()["data"])
        self.assertEqual(self.call("get", "/assets/999", "admin_maya").status_code, 404)
        r = self.call("get", "/assets/search?criticality=Critical", "admin_maya")
        self.assertTrue(all(a["criticality_level"] == "Critical" for a in r.get_json()["data"]["assets"]))
        r = self.call("get", "/assets/search?name=server&department=it", "auditor_sara")
        self.assertGreaterEqual(r.get_json()["data"]["count"], 1)
        self.assertEqual(self.call("get", "/assets/search?criticality=Huge", "admin_maya").status_code, 400)
        r = self.call("get", "/assets/search?name=' OR '1'='1", "admin_maya")
        self.assertEqual(r.get_json()["data"]["count"], 0)


class IncidentsTests(ApiTestCase):
    def test_full_lifecycle(self):
        body = {"title": "Lifecycle test", "description": "d", "category": "Data Leakage",
                "severity": "High", "asset_id": 3}
        r = self.call("post", "/incidents", "user_rami", json=body)
        self.assertEqual(r.status_code, 201)
        iid = r.get_json()["data"]["incident_id"]
        self.assertEqual(self.call("post", "/incidents", "analyst_karim", json=body).status_code, 403)

        bad = {"status": "Closed"}
        self.assertEqual(self.call("put", f"/incidents/{iid}/status", "admin_maya", json=bad).status_code, 400)
        self.assertEqual(self.call("put", f"/incidents/{iid}/assign", "admin_maya",
                                   json={"analyst_id": 4}).status_code, 400)  # not an analyst
        self.assertEqual(self.call("put", f"/incidents/{iid}/assign", "analyst_karim",
                                   json={"analyst_id": 2}).status_code, 403)
        r = self.call("put", f"/incidents/{iid}/assign", "admin_maya", json={"analyst_id": 2})
        self.assertEqual(r.get_json()["data"]["assigned_analyst_username"], "analyst_karim")

        self.assertEqual(self.call("get", f"/incidents/{iid}", "analyst_lina").status_code, 403)
        for status in ["Under Investigation", "Mitigated", "Resolved"]:
            r = self.call("put", f"/incidents/{iid}/status", "analyst_karim", json={"status": status})
            self.assertEqual(r.status_code, 200, r.get_json())
        self.assertIsNotNone(r.get_json()["data"]["resolution_date"])
        r = self.call("post", f"/incidents/{iid}/notes", "analyst_karim", json={"note_content": "Root cause found"})
        self.assertEqual(r.status_code, 201)
        self.assertEqual(len(r.get_json()["data"]["incident"]["notes"]), 1)
        self.assertEqual(self.call("put", f"/incidents/{iid}/status", "analyst_karim",
                                   json={"status": "Closed"}).status_code, 403)
        self.assertEqual(self.call("put", f"/incidents/{iid}/status", "admin_maya",
                                   json={"status": "Closed"}).status_code, 200)
        self.assertEqual(self.call("put", f"/incidents/{iid}/status", "admin_maya",
                                   json={"status": "Open"}).status_code, 400)
        notif = connect_to_db().execute("SELECT COUNT(*) FROM notifications WHERE user_id = 2").fetchone()[0]
        self.assertGreaterEqual(notif, 1)

    def test_reads(self):
        self.assertEqual(self.call("get", "/incidents", "auditor_sara").get_json()["data"]["count"] >= 4, True)
        self.assertEqual(self.call("get", "/incidents", "user_rami").status_code, 403)
        self.assertEqual(self.call("get", "/incidents/2", "user_rami").status_code, 200)   # reported by rami
        self.assertEqual(self.call("get", "/incidents/1", "user_rami").status_code, 403)   # not his
        self.assertEqual(self.call("get", "/incidents/999", "admin_maya").status_code, 404)

    def test_create_validation(self):
        r = self.call("post", "/incidents", "admin_maya", json={"title": "x", "severity": "Extreme"})
        self.assertEqual(r.status_code, 400)
        r = self.call("post", "/incidents", "admin_maya", json={"title": "x", "description": "y",
                                                               "category": "Other", "severity": "Low",
                                                               "asset_id": 999})
        self.assertEqual(r.status_code, 404)


if __name__ == "__main__":
    unittest.main()
