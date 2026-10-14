# API tests for Services 4-6 (Threat Intelligence, Security Audit Logging, Security Reports)
# Zeinab Harb
# Run from the project folder:  python -m unittest discover tests -v
# Reuses Maya's ApiTestCase (throwaway database, seeded data, one token per role).
from datetime import datetime, timezone

from test_api import ApiTestCase

from database import connect_to_db


def db_count(sql, params=()):
    conn = connect_to_db()
    try:
        return conn.execute(sql, params).fetchone()[0]
    finally:
        conn.close()


def user_id(username):
    conn = connect_to_db()
    try:
        return conn.execute("SELECT user_id FROM users WHERE username = ?", (username,)).fetchone()[0]
    finally:
        conn.close()


THREAT = {"threat_type": "IP Address", "threat_value": "192.0.2.77", "description": "Port scanner",
          "severity_level": "Medium", "source": "Firewall"}


class ThreatTests(ApiTestCase):
    def test_add_threat_and_duplicate(self):
        r = self.call("post", "/threats", "admin_maya", json=THREAT)
        self.assertEqual(r.status_code, 201, r.get_json())
        self.assertEqual(r.get_json()["developer"], "Zeinab Harb")
        self.assertEqual(r.get_json()["data"]["threat_value"], "192.0.2.77")
        # same type + value (with extra whitespace) is a duplicate
        dup = dict(THREAT, threat_value=" 192.0.2.77 ")
        self.assertEqual(self.call("post", "/threats", "admin_maya", json=dup).status_code, 409)
        self.assertEqual(db_count("SELECT COUNT(*) FROM logs WHERE action_performed = 'THREAT_CREATED'"), 1)

    def test_domain_and_hash_are_normalized_for_duplicates(self):
        body = {"threat_type": "Domain", "threat_value": "Login-Update.EXAMPLE.org", "description": "Phishing",
                "severity_level": "High", "source": "PhishTank"}
        r = self.call("post", "/threats", "admin_maya", json=body)
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.get_json()["data"]["threat_value"], "login-update.example.org")
        body["threat_value"] = "login-update.example.org"
        self.assertEqual(self.call("post", "/threats", "admin_maya", json=body).status_code, 409)

    def test_threat_validation(self):
        cases = [
            ({"threat_type": "IP Address", "threat_value": "300.1.1.1"}, "threat_value"),
            ({"threat_type": "Domain", "threat_value": "not a domain"}, "threat_value"),
            ({"threat_type": "File Hash", "threat_value": "abc123"}, "threat_value"),
            ({"threat_type": "Ransomware"}, "threat_type"),
            ({"severity_level": "Extreme"}, "severity_level"),
        ]
        for change, field in cases:
            with self.subTest(change=change):
                r = self.call("post", "/threats", "admin_maya", json=dict(THREAT, **change))
                self.assertEqual(r.status_code, 400)
                self.assertIn(field, r.get_json()["errors"])
        r = self.call("post", "/threats", "admin_maya", json={"threat_type": "Domain"})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.call("post", "/threats", "admin_maya", json=dict(THREAT, extra=1)).status_code, 400)

    def test_threat_permissions(self):
        self.assertEqual(self.call("post", "/threats", "analyst_karim", json=THREAT).status_code, 403)
        self.assertEqual(self.call("post", "/threats", "auditor_sara", json=THREAT).status_code, 403)
        for who in ("admin_maya", "analyst_karim", "auditor_sara"):
            self.assertEqual(self.call("get", "/threats", who).status_code, 200)
            self.assertEqual(self.call("get", "/threats/1", who).status_code, 200)
            self.assertEqual(self.call("get", "/threats/search?severity=High", who).status_code, 200)
        self.assertEqual(self.call("get", "/threats", "user_rami").status_code, 403)
        self.assertEqual(self.call("get", "/threats").status_code, 401)
        self.assertEqual(self.call("delete", "/threats/1", "analyst_karim").status_code, 403)

    def test_get_all_and_specific(self):
        r = self.call("get", "/threats", "auditor_sara")
        data = r.get_json()["data"]
        self.assertEqual(data["count"], db_count("SELECT COUNT(*) FROM threats"))
        self.assertTrue({"severity_level", "source", "date_added"} <= set(data["threats"][0]))
        self.assertEqual(self.call("get", "/threats/99999", "admin_maya").status_code, 404)

    def test_search(self):
        r = self.call("get", "/threats/search?type=Domain", "analyst_karim")
        self.assertTrue(all(t["threat_type"] == "Domain" for t in r.get_json()["data"]["threats"]))
        r = self.call("get", "/threats/search?severity=Critical&source=soc", "admin_maya")
        for t in r.get_json()["data"]["threats"]:
            self.assertEqual(t["severity_level"], "Critical")
            self.assertIn("soc", t["source"].lower())
        r = self.call("get", "/threats/search?value=' OR '1'='1", "admin_maya")
        self.assertEqual(r.get_json()["data"]["count"], 0)
        self.assertEqual(self.call("get", "/threats/search", "admin_maya").status_code, 400)
        self.assertEqual(self.call("get", "/threats/search?severity=Huge", "admin_maya").status_code, 400)
        self.assertEqual(self.call("get", "/threats/search?colour=red", "admin_maya").status_code, 400)

    def test_update_threat(self):
        body = dict(THREAT, threat_value="192.0.2.88")
        threat_id = self.call("post", "/threats", "admin_maya", json=body).get_json()["data"]["threat_id"]
        r = self.call("put", f"/threats/{threat_id}", "admin_maya",
                      json={"severity_level": "Critical", "source": "CERT"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["data"]["before"]["severity_level"], "Medium")
        self.assertEqual(r.get_json()["data"]["after"]["severity_level"], "Critical")
        self.assertEqual(self.call("put", f"/threats/{threat_id}", "admin_maya",
                                   json={"threat_value": "1.1.1.1"}).status_code, 400)
        self.assertEqual(self.call("put", f"/threats/{threat_id}", "admin_maya",
                                   json={"severity_level": "Bad"}).status_code, 400)
        self.assertEqual(self.call("put", f"/threats/{threat_id}", "analyst_karim",
                                   json={"source": "x"}).status_code, 403)
        self.assertEqual(self.call("put", "/threats/99999", "admin_maya", json={"source": "x"}).status_code, 404)

    def test_delete_threat(self):
        body = dict(THREAT, threat_value="192.0.2.99")
        threat_id = self.call("post", "/threats", "admin_maya", json=body).get_json()["data"]["threat_id"]
        self.assertEqual(self.call("delete", f"/threats/{threat_id}", "auditor_sara").status_code, 403)
        self.assertEqual(self.call("delete", f"/threats/{threat_id}", "admin_maya").status_code, 200)
        self.assertEqual(self.call("get", f"/threats/{threat_id}", "admin_maya").status_code, 404)


LOG = {"user_id": 2, "action_performed": "malware scan completed", "description": "Weekly scan finished",
       "severity_level": "Information", "related_service": "Asset Management"}


class LogTests(ApiTestCase):
    def test_create_log(self):
        r = self.call("post", "/logs", "admin_maya", json=LOG)
        self.assertEqual(r.status_code, 201, r.get_json())
        self.assertEqual(r.get_json()["data"]["action_performed"], "MALWARE_SCAN_COMPLETED")
        self.assertEqual(r.get_json()["developer"], "Zeinab Harb")
        bad = {"user_id": "two", "action_performed": "!", "description": "x", "severity_level": "Loud",
               "related_service": "Kitchen"}
        r = self.call("post", "/logs", "admin_maya", json=bad)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(set(r.get_json()["errors"]),
                         {"user_id", "action_performed", "severity_level", "related_service"})
        self.assertEqual(self.call("post", "/logs", "admin_maya", json=dict(LOG, user_id=99999)).status_code, 404)
        self.assertEqual(self.call("post", "/logs", "auditor_sara", json=LOG).status_code, 403)

    def test_log_permissions(self):
        self.assertEqual(self.call("get", "/logs", "admin_maya").status_code, 200)
        self.assertEqual(self.call("get", "/logs", "auditor_sara").status_code, 200)
        self.assertEqual(self.call("get", "/logs", "analyst_karim").status_code, 403)
        self.assertEqual(self.call("get", "/logs/1", "analyst_karim").status_code, 200)
        self.assertEqual(self.call("get", "/logs/search?action=login", "analyst_karim").status_code, 200)
        self.assertEqual(self.call("get", "/logs/user/1", "analyst_karim").status_code, 403)
        for url in ("/logs", "/logs/1", "/logs/search?action=login", "/logs/user/1"):
            self.assertEqual(self.call("get", url, "user_rami").status_code, 403)

    def test_get_specific_log(self):
        r = self.call("get", "/logs/1", "auditor_sara")
        self.assertEqual(r.status_code, 200)
        self.assertTrue({"log_id", "user_id", "username", "action_performed", "timestamp", "severity_level",
                         "related_service"} <= set(r.get_json()["data"]))
        self.assertEqual(self.call("get", "/logs/99999", "auditor_sara").status_code, 404)

    def test_search_logs(self):
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        r = self.call("get", f"/logs/search?date={today}&action=LOGIN_SUCCESS", "auditor_sara")
        logs = r.get_json()["data"]["logs"]
        self.assertGreaterEqual(len(logs), 1)
        self.assertTrue(all(l["action_performed"] == "LOGIN_SUCCESS" for l in logs))
        r = self.call("get", "/logs/search?user=analyst_karim", "admin_maya")
        self.assertTrue(all(l["username"] == "analyst_karim" for l in r.get_json()["data"]["logs"]))
        r = self.call("get", "/logs/search?severity=Warning&service=identity", "admin_maya")
        self.assertTrue(all(l["severity_level"] == "Warning" for l in r.get_json()["data"]["logs"]))
        self.assertEqual(self.call("get", "/logs/search?date=14-10-2026", "admin_maya").status_code, 400)
        self.assertEqual(self.call("get", "/logs/search?severity=Panic", "admin_maya").status_code, 400)
        self.assertEqual(self.call("get", "/logs/search", "admin_maya").status_code, 400)

    def test_logs_by_user(self):
        sara = user_id("auditor_sara")
        r = self.call("get", f"/logs/user/{sara}", "auditor_sara")
        data = r.get_json()["data"]
        self.assertEqual(data["count"], db_count("SELECT COUNT(*) FROM logs WHERE user_id = ?", (sara,)))
        self.assertTrue(all(l["user_id"] == sara for l in data["logs"]))
        # a brand-new account has no recorded activity yet
        conn = connect_to_db()
        try:
            new_id = conn.execute(
                "INSERT INTO users (full_name, username, email, password_hash, department, role) "
                "VALUES ('No Logs', 'no_logs_user', 'nologs@company.com', 'x', 'Ops', 'Regular User')").lastrowid
            conn.commit()
        finally:
            conn.close()
        r = self.call("get", f"/logs/user/{new_id}", "admin_maya")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["data"]["count"], 0)
        self.assertEqual(self.call("get", "/logs/user/99999", "admin_maya").status_code, 404)

    def test_logs_cannot_be_modified(self):
        r = self.call("put", "/logs/1", "admin_maya", json={"description": "tampered"})
        self.assertEqual(r.status_code, 405)
        self.assertEqual(self.call("patch", "/logs/1", "admin_maya", json={"description": "x"}).status_code, 405)
        self.assertNotEqual(self.call("get", "/logs/1", "admin_maya").get_json()["data"]["description"], "tampered")

    def test_delete_log(self):
        log_id = self.call("post", "/logs", "admin_maya", json=LOG).get_json()["data"]["log_id"]
        self.assertEqual(self.call("delete", f"/logs/{log_id}", "analyst_karim").status_code, 403)
        self.assertEqual(self.call("delete", f"/logs/{log_id}", "auditor_sara").status_code, 403)
        self.assertEqual(self.call("delete", f"/logs/{log_id}", "admin_maya").status_code, 200)
        self.assertEqual(self.call("get", f"/logs/{log_id}", "admin_maya").status_code, 404)
        self.assertGreaterEqual(db_count("SELECT COUNT(*) FROM logs WHERE action_performed = 'LOG_DELETED'"), 1)


class ReportTests(ApiTestCase):
    REPORTS = ["summary", "incidents", "assets", "threats", "vulnerabilities", "activity"]

    def test_report_permissions(self):
        for name in self.REPORTS:
            with self.subTest(report=name):
                self.assertEqual(self.call("get", f"/reports/{name}", "admin_maya").status_code, 200)
                self.assertEqual(self.call("get", f"/reports/{name}", "auditor_sara").status_code, 200)
                self.assertEqual(self.call("get", f"/reports/{name}", "analyst_karim").status_code, 403)
                self.assertEqual(self.call("get", f"/reports/{name}", "user_rami").status_code, 403)

    def test_summary_matches_database(self):
        data = self.call("get", "/reports/summary", "auditor_sara").get_json()["data"]
        self.assertEqual(data["users"], db_count("SELECT COUNT(*) FROM users"))
        self.assertEqual(data["assets"], db_count("SELECT COUNT(*) FROM assets"))
        self.assertEqual(data["open_incidents"],
                         db_count("SELECT COUNT(*) FROM incidents WHERE status NOT IN ('Resolved', 'Closed')"))
        self.assertEqual(data["critical_threats"],
                         db_count("SELECT COUNT(*) FROM threats WHERE severity_level = 'Critical'"))

    def test_threat_report_matches_database(self):
        data = self.call("get", "/reports/threats", "admin_maya").get_json()["data"]
        self.assertEqual(data["total_threats"], db_count("SELECT COUNT(*) FROM threats"))
        self.assertEqual(sum(data["threats_by_severity"].values()), data["total_threats"])
        self.assertEqual(sum(data["threats_by_type"].values()), data["total_threats"])
        for severity, count in data["threats_by_severity"].items():
            self.assertEqual(count, db_count("SELECT COUNT(*) FROM threats WHERE severity_level = ?", (severity,)))

    def test_incident_asset_vulnerability_reports(self):
        inc = self.call("get", "/reports/incidents", "admin_maya").get_json()["data"]
        self.assertEqual(sum(inc["incidents_by_severity"].values()), inc["total_incidents"])
        self.assertEqual(sum(inc["incidents_by_status"].values()), inc["total_incidents"])
        assets = self.call("get", "/reports/assets", "admin_maya").get_json()["data"]
        self.assertEqual(sum(assets["assets_by_type"].values()), assets["total_assets"])
        self.assertEqual(assets["critical_assets"], len(assets["critical_asset_list"]))
        vul = self.call("get", "/reports/vulnerabilities", "admin_maya").get_json()["data"]
        self.assertEqual(vul["total_vulnerabilities"], db_count("SELECT COUNT(*) FROM vulnerabilities"))
        self.assertEqual(sum(vul["vulnerabilities_by_status"].values()), vul["total_vulnerabilities"])
        self.assertEqual(vul["critical_vulnerabilities"], vul["vulnerabilities_by_severity"]["Critical"])

    def test_activity_report_matches_logs(self):
        data = self.call("get", "/reports/activity", "auditor_sara").get_json()["data"]
        self.assertEqual(data["total_user_activities"], db_count("SELECT COUNT(*) FROM logs"))
        self.assertEqual(data["failed_login_attempts"],
                         db_count("SELECT COUNT(*) FROM logs WHERE action_performed = 'LOGIN_FAILED'"))
        self.assertEqual(data["login_attempts"], data["successful_logins"] + data["failed_login_attempts"])
        top = data["most_performed_actions"][0]
        self.assertEqual(top["count"], db_count("SELECT COUNT(*) FROM logs WHERE action_performed = ?",
                                                (top["action"],)))
