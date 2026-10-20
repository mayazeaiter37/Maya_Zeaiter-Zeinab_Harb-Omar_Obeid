# API tests for Services 7-9 (Vulnerability Management, Notifications and Alerts, Security Playbooks)
# Omar Obeid
# Run from the project folder:  python -m unittest discover tests -v
# Reuses Maya's ApiTestCase (throwaway database, seeded data, one token per role).
from test_api import ApiTestCase

from database import connect_to_db


def db_count(sql, params=()):
    conn = connect_to_db()
    try:
        return conn.execute(sql, params).fetchone()[0]
    finally:
        conn.close()


VULN = {"title": "Apache path traversal", "description": "Path traversal and RCE in Apache HTTP Server 2.4.49",
        "cve_identifier": "CVE-2021-41773", "cvss_score": 7.5, "severity_level": "High",
        "affected_asset_id": 1, "discovery_source": "Nessus scan"}


class VulnerabilityTests(ApiTestCase):
    def create(self, **changes):
        r = self.call("post", "/vulnerabilities", "admin_maya", json=dict(VULN, **changes))
        self.assertEqual(r.status_code, 201, r.get_json())
        return r.get_json()["data"]

    def test_create_and_duplicate(self):
        data = self.create(cve_identifier="cve-2021-41773", affected_asset_id=4)
        self.assertEqual(data["cve_identifier"], "CVE-2021-41773")
        self.assertEqual(data["status"], "Open")
        self.assertEqual(data["affected_asset"]["asset_id"], 4)
        r = self.call("post", "/vulnerabilities", "admin_maya", json=dict(VULN, affected_asset_id=4))
        self.assertEqual(r.status_code, 409)
        self.assertEqual(r.get_json()["developer"], "Omar Obeid")
        # High severity alerts the asset owner
        self.assertEqual(db_count("SELECT COUNT(*) FROM notifications WHERE notification_type = 'Vulnerability Alert' "
                                  "AND message LIKE '%CVE-2021-41773%'"), 1)
        self.assertEqual(db_count("SELECT COUNT(*) FROM logs WHERE action_performed = 'VULNERABILITY_CREATED'"), 1)

    def test_create_validation(self):
        cases = [
            ({"cve_identifier": "CVE-21-1234"}, "cve_identifier"),
            ({"cve_identifier": "CVE-2021-12"}, "cve_identifier"),
            ({"cve_identifier": "2021-41773"}, "cve_identifier"),
            ({"cvss_score": 11}, "cvss_score"),
            ({"cvss_score": -1}, "cvss_score"),
            ({"cvss_score": "high"}, "cvss_score"),
            ({"severity_level": "Severe"}, "severity_level"),
            ({"cvss_score": 9.8, "severity_level": "Low"}, "severity_level"),
        ]
        for change, field in cases:
            with self.subTest(change=change):
                r = self.call("post", "/vulnerabilities", "admin_maya", json=dict(VULN, **change))
                self.assertEqual(r.status_code, 400)
                self.assertIn(field, r.get_json()["errors"])
        r = self.call("post", "/vulnerabilities", "admin_maya", json=dict(VULN, affected_asset_id=999))
        self.assertEqual(r.status_code, 404)
        r = self.call("post", "/vulnerabilities", "admin_maya", json={"title": "Only a title"})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.call("post", "/vulnerabilities", "admin_maya", json=dict(VULN, x=1)).status_code, 400)

    def test_permissions(self):
        self.assertEqual(self.call("post", "/vulnerabilities", "analyst_karim", json=VULN).status_code, 403)
        self.assertEqual(self.call("get", "/vulnerabilities", "user_rami").status_code, 403)
        self.assertEqual(self.call("get", "/vulnerabilities").status_code, 401)
        for who in ("admin_maya", "analyst_karim", "auditor_sara"):
            self.assertEqual(self.call("get", "/vulnerabilities", who).status_code, 200)
            self.assertEqual(self.call("get", "/vulnerabilities/1", who).status_code, 200)
            self.assertEqual(self.call("get", "/vulnerabilities/search?severity=High", who).status_code, 200)
        self.assertEqual(self.call("put", "/vulnerabilities/1", "auditor_sara",
                                   json={"description": "x"}).status_code, 403)
        self.assertEqual(self.call("delete", "/vulnerabilities/1", "analyst_karim").status_code, 403)
        self.assertEqual(self.call("get", "/vulnerabilities/99999", "admin_maya").status_code, 404)

    def test_status_flow(self):
        vid = self.create(cve_identifier="CVE-2023-44487", cvss_score=7.5, affected_asset_id=2)["vulnerability_id"]
        url = f"/vulnerabilities/{vid}"
        r = self.call("put", url, "analyst_karim", json={"status": "Resolved"})  # skipping steps
        self.assertEqual(r.status_code, 400)
        for status in ("Under Investigation", "In Progress"):
            self.assertEqual(self.call("put", url, "analyst_karim", json={"status": status}).status_code, 200)
        r = self.call("put", url, "analyst_karim", json={"status": "In Progress", "resolution_date": "2026-01-01"})
        self.assertEqual(r.status_code, 400)  # resolution date before resolution
        r = self.call("put", url, "analyst_karim", json={"status": "Resolved"})
        self.assertEqual(r.status_code, 200)
        self.assertIsNotNone(r.get_json()["data"]["after"]["resolution_date"])
        self.assertEqual(self.call("put", url, "admin_maya", json={"status": "Closed"}).status_code, 200)
        r = self.call("put", url, "admin_maya", json={"status": "Open"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("already Closed", r.get_json()["message"])

    def test_update_fields(self):
        vid = self.create(cve_identifier="CVE-2022-22965", cvss_score=9.8, severity_level="Critical",
                          affected_asset_id=3)["vulnerability_id"]
        url = f"/vulnerabilities/{vid}"
        r = self.call("put", url, "analyst_karim", json={"cvss_score": 8.1, "severity_level": "High",
                                                          "description": "Spring4Shell, mitigated by WAF rule"})
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertEqual(r.get_json()["data"]["before"]["cvss_score"], 9.8)
        self.assertEqual(r.get_json()["data"]["after"]["severity_level"], "High")
        self.assertEqual(self.call("put", url, "admin_maya", json={"cvss_score": 3.0}).status_code, 400)
        self.assertEqual(self.call("put", url, "admin_maya", json={"cve_identifier": "CVE-2020-0001"}).status_code,
                         400)
        self.assertEqual(self.call("put", url, "admin_maya", json={"resolution_date": "yesterday"}).status_code, 400)

    def test_search(self):
        r = self.call("get", "/vulnerabilities/search?cve=2024-6387", "analyst_karim")
        self.assertEqual(r.get_json()["data"]["count"], 1)
        r = self.call("get", "/vulnerabilities/search?severity=Critical&status=In Progress", "auditor_sara")
        self.assertTrue(all(v["severity_level"] == "Critical" and v["status"] == "In Progress"
                            for v in r.get_json()["data"]["vulnerabilities"]))
        r = self.call("get", "/vulnerabilities/search?asset=1", "admin_maya")
        self.assertEqual(r.get_json()["data"]["count"],
                         db_count("SELECT COUNT(*) FROM vulnerabilities WHERE affected_asset_id = 1"))
        self.assertEqual(self.call("get", "/vulnerabilities/search?cve=' OR '1'='1",
                                   "admin_maya").get_json()["data"]["count"], 0)
        for bad in ("", "?severity=Huge", "?asset=abc", "?color=red"):
            self.assertEqual(self.call("get", f"/vulnerabilities/search{bad}", "admin_maya").status_code, 400)

    def test_delete(self):
        vid = self.create(cve_identifier="CVE-2020-1472", cvss_score=10.0, severity_level="Critical",
                          affected_asset_id=6)["vulnerability_id"]
        self.assertEqual(self.call("delete", f"/vulnerabilities/{vid}", "admin_maya").status_code, 200)
        self.assertEqual(self.call("delete", f"/vulnerabilities/{vid}", "admin_maya").status_code, 404)
        self.assertEqual(db_count("SELECT COUNT(*) FROM logs WHERE action_performed = 'VULNERABILITY_DELETED'"), 1)


NOTE = {"user_id": 4, "title": "Suspicious login", "message": "New login to your account from 203.0.113.45",
        "notification_type": "Security Alert", "severity_level": "High"}


class NotificationTests(ApiTestCase):
    def test_create(self):
        r = self.call("post", "/notifications", "admin_maya", json=NOTE)
        self.assertEqual(r.status_code, 201, r.get_json())
        data = r.get_json()["data"]
        self.assertEqual((data["status"], data["read_date"], data["username"]), ("Unread", None, "user_rami"))
        self.assertEqual(r.get_json()["developer"], "Omar Obeid")
        for change, code in (({"notification_type": "Spam"}, 400), ({"severity_level": "Info"}, 400),
                             ({"user_id": 999}, 404), ({"user_id": 6}, 400), ({"title": " "}, 400)):
            with self.subTest(change=change):
                self.assertEqual(self.call("post", "/notifications", "admin_maya",
                                           json=dict(NOTE, **change)).status_code, code)
        self.assertEqual(self.call("post", "/notifications", "user_rami", json=NOTE).status_code, 403)
        self.assertEqual(self.call("post", "/notifications", "analyst_karim", json=NOTE).status_code, 403)
        self.assertEqual(self.call("post", "/notifications", "auditor_sara", json=NOTE).status_code, 403)

    def test_user_notifications(self):
        r = self.call("get", "/notifications/user/4", "user_rami")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["data"]["count"],
                         db_count("SELECT COUNT(*) FROM notifications WHERE user_id = 4"))
        r = self.call("get", "/notifications/user/3", "admin_maya")  # analyst_lina has none
        self.assertEqual(r.status_code, 200)
        self.assertEqual((r.get_json()["data"]["count"], r.get_json()["data"]["notifications"]), (0, []))
        self.assertEqual(self.call("get", "/notifications/user/2", "user_rami").status_code, 403)
        self.assertEqual(self.call("get", "/notifications/user/2", "auditor_sara").status_code, 200)
        self.assertEqual(self.call("get", "/notifications/user/999", "admin_maya").status_code, 404)

    def test_get_and_mark_read(self):
        nid = self.call("post", "/notifications", "admin_maya", json=NOTE).get_json()["data"]["notification_id"]
        self.assertEqual(self.call("get", f"/notifications/{nid}", "user_rami").status_code, 200)
        self.assertEqual(self.call("get", f"/notifications/{nid}", "analyst_karim").status_code, 403)
        self.assertEqual(self.call("put", f"/notifications/{nid}/read", "analyst_karim").status_code, 403)
        self.assertEqual(self.call("put", f"/notifications/{nid}/read", "auditor_sara").status_code, 403)
        r = self.call("put", f"/notifications/{nid}/read", "user_rami")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()["data"]
        self.assertEqual(data["status"], "Read")
        self.assertIsNotNone(data["read_date"])
        again = self.call("put", f"/notifications/{nid}/read", "user_rami").get_json()
        self.assertEqual(again["data"]["read_date"], data["read_date"])  # first read time is kept
        self.assertEqual(self.call("get", "/notifications/99999", "admin_maya").status_code, 404)

    def test_search(self):
        r = self.call("get", "/notifications/search?type=System Notification&status=Unread", "admin_maya")
        rows = r.get_json()["data"]["notifications"]
        self.assertEqual(len(rows), db_count("SELECT COUNT(*) FROM notifications WHERE notification_type = "
                                             "'System Notification' AND status = 'Unread'"))
        r = self.call("get", "/notifications/search?user=analyst_karim", "auditor_sara")
        self.assertTrue(all(n["user_id"] == 2 for n in r.get_json()["data"]["notifications"]))
        r = self.call("get", "/notifications/search?status=Unread", "analyst_karim")  # own inbox only
        self.assertTrue(r.get_json()["data"]["notifications"])
        self.assertTrue(all(n["user_id"] == 2 for n in r.get_json()["data"]["notifications"]))
        self.assertEqual(self.call("get", "/notifications/search?user=4", "analyst_karim").status_code, 403)
        self.assertEqual(self.call("get", "/notifications/search?status=Unread", "user_rami").status_code, 403)
        for bad in ("", "?status=Seen", "?type=Spam", "?colour=red"):
            self.assertEqual(self.call("get", f"/notifications/search{bad}", "admin_maya").status_code, 400)

    def test_delete(self):
        nid = self.call("post", "/notifications", "admin_maya", json=NOTE).get_json()["data"]["notification_id"]
        self.assertEqual(self.call("delete", f"/notifications/{nid}", "user_rami").status_code, 403)
        self.assertEqual(self.call("delete", f"/notifications/{nid}", "admin_maya").status_code, 200)
        self.assertEqual(self.call("delete", f"/notifications/{nid}", "admin_maya").status_code, 404)


PLAYBOOK = {"playbook_name": "DDoS Mitigation", "description": "Keep public services online during a flood",
            "incident_category": "Denial of Service", "severity_level": "High"}


class PlaybookTests(ApiTestCase):
    def create(self, name):
        r = self.call("post", "/playbooks", "admin_maya", json=dict(PLAYBOOK, playbook_name=name))
        self.assertEqual(r.status_code, 201, r.get_json())
        return r.get_json()["data"]["playbook_id"]

    def add_step(self, pid, step, who="admin_maya", **extra):
        return self.call("post", f"/playbooks/{pid}/actions", who,
                         json=dict({"action_description": f"Step {step} task", "step_number": step}, **extra))

    def test_create_playbook(self):
        pid = self.create("Data Leak Response")
        self.assertEqual(self.call("post", "/playbooks", "admin_maya",
                                   json=dict(PLAYBOOK, playbook_name="data leak RESPONSE")).status_code, 409)
        for change in ({"incident_category": "Alien Invasion"}, {"severity_level": "Urgent"}, {"playbook_name": ""}):
            self.assertEqual(self.call("post", "/playbooks", "admin_maya",
                                       json=dict(PLAYBOOK, **change)).status_code, 400)
        self.assertEqual(self.call("post", "/playbooks", "analyst_karim", json=PLAYBOOK).status_code, 403)
        r = self.call("get", f"/playbooks/{pid}", "auditor_sara")
        self.assertEqual(r.get_json()["data"]["created_by"], 1)
        self.assertEqual(r.get_json()["developer"], "Omar Obeid")

    def test_list_and_get_permissions(self):
        for who in ("admin_maya", "analyst_karim", "auditor_sara"):
            self.assertEqual(self.call("get", "/playbooks", who).status_code, 200)
        self.assertEqual(self.call("get", "/playbooks", "user_rami").status_code, 403)
        self.assertEqual(self.call("get", "/playbooks/1", "user_rami").status_code, 403)
        self.assertEqual(self.call("get", "/playbooks/99999", "admin_maya").status_code, 404)

    def test_actions_are_ordered_and_unique(self):
        pid = self.create("Insider Threat")
        for step in (3, 1, 2):
            self.assertEqual(self.add_step(pid, step, "analyst_karim").status_code, 201)
        self.assertEqual(self.add_step(pid, 2).status_code, 409)
        self.assertEqual(self.add_step(pid, 0).status_code, 400)
        self.assertEqual(self.add_step(pid, 4, assigned_user_id=4).status_code, 400)  # regular user
        self.assertEqual(self.add_step(99999, 1).status_code, 404)
        self.assertEqual(self.add_step(pid, 5, "auditor_sara").status_code, 403)
        steps = self.call("get", f"/playbooks/{pid}", "analyst_karim").get_json()["data"]["actions"]
        self.assertEqual([a["step_number"] for a in steps], [1, 2, 3])

    def test_action_status_flow(self):
        pid = self.create("Web Defacement")
        a1 = self.add_step(pid, 1).get_json()["data"]["action"]["action_id"]
        a2 = self.add_step(pid, 2, assigned_user_id=3).get_json()["data"]["action"]["action_id"]
        self.assertEqual(db_count("SELECT COUNT(*) FROM notifications WHERE user_id = 3 AND message LIKE "
                                  "'%Web Defacement%'"), 1)
        url1, url2 = f"/actions/{a1}/status", f"/actions/{a2}/status"
        self.assertEqual(self.call("put", url1, "analyst_karim", json={"status": "Completed"}).status_code, 400)
        r = self.call("put", url2, "admin_maya", json={"status": "In Progress"})
        self.assertEqual(r.status_code, 409)  # step 1 not completed yet
        r = self.call("put", url1, "analyst_karim", json={"status": "In Progress"})
        self.assertEqual(r.get_json()["data"]["after"]["assigned_user_id"], 2)  # starter owns the step
        self.assertEqual(self.call("put", url1, "analyst_karim",
                                   json={"status": "Completed", "completion_date": "not a date"}).status_code, 400)
        r = self.call("put", url1, "analyst_karim", json={"status": "Completed"})
        self.assertEqual(r.status_code, 200)
        self.assertIsNotNone(r.get_json()["data"]["after"]["completion_date"])
        self.assertEqual(r.get_json()["data"]["playbook_progress"]["completed_steps"], 1)
        # step 2 belongs to analyst_lina: karim may not touch it
        self.assertEqual(self.call("put", url2, "analyst_karim", json={"status": "In Progress"}).status_code, 403)
        self.assertEqual(self.call("put", url2, "auditor_sara", json={"status": "In Progress"}).status_code, 403)
        r = self.call("put", url2, "analyst_lina", json={"status": "In Progress"})
        self.assertEqual(r.status_code, 200)
        r = self.call("put", url2, "analyst_lina", json={"status": "Completed", "completion_date": "2026-10-10"})
        self.assertEqual(r.get_json()["data"]["after"]["completion_date"], "2026-10-10 00:00:00")
        self.assertEqual(self.call("put", url2, "admin_maya", json={"status": "Pending"}).status_code, 400)
        self.assertEqual(self.call("put", "/actions/99999/status", "admin_maya",
                                   json={"status": "In Progress"}).status_code, 404)

    def test_delete_playbook_removes_actions(self):
        pid = self.create("Temporary Playbook")
        self.add_step(pid, 1)
        self.add_step(pid, 2)
        self.assertEqual(self.call("delete", f"/playbooks/{pid}", "analyst_karim").status_code, 403)
        r = self.call("delete", f"/playbooks/{pid}", "admin_maya")
        self.assertEqual(r.get_json()["data"]["deleted_actions"], 2)
        self.assertEqual(db_count("SELECT COUNT(*) FROM response_actions WHERE playbook_id = ?", (pid,)), 0)
        self.assertEqual(self.call("delete", f"/playbooks/{pid}", "admin_maya").status_code, 404)
