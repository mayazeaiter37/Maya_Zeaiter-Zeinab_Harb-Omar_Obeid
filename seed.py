# Creates the database and inserts sample data for Services 1-3
# Maya Zeaiter
#
# Test accounts (local development only):
#   admin_maya     / Admin@1234    Security Administrator
#   analyst_karim  / Analyst@1234  Security Analyst
#   analyst_lina   / Analyst@1234  Security Analyst
#   user_rami      / User@1234     Regular User
#   auditor_sara   / Auditor@1234  Auditor
#   user_suspended / User@1234     Regular User (Suspended)
import os
import sys

from werkzeug.security import generate_password_hash

from database import DB_PATH, connect_to_db, init_db

USERS = [
    ("Maya Zeaiter", "admin_maya", "maya.admin@company.com", "Admin@1234", "IT Security", "Security Administrator", "Active"),
    ("Karim Haddad", "analyst_karim", "karim@company.com", "Analyst@1234", "SOC", "Security Analyst", "Active"),
    ("Lina Khoury", "analyst_lina", "lina@company.com", "Analyst@1234", "SOC", "Security Analyst", "Active"),
    ("Rami Nassar", "user_rami", "rami@company.com", "User@1234", "Finance", "Regular User", "Active"),
    ("Sara Daher", "auditor_sara", "sara@company.com", "Auditor@1234", "Compliance", "Auditor", "Active"),
    ("Omar Fares", "user_suspended", "omar@company.com", "User@1234", "Sales", "Regular User", "Suspended"),
]

ASSETS = [
    ("Main Web Server", "Server", "10.0.0.10", "Ubuntu 22.04", 1, "IT Security", "Data Center A", "Critical", "Active"),
    ("Finance Workstation 07", "Workstation", "10.0.2.57", "Windows 11", 4, "Finance", "Floor 2", "Medium", "Active"),
    ("Customer Database", "Database", "10.0.1.20", "Oracle Linux 9", 1, "IT Security", "Data Center A", "Critical", "Active"),
    ("HR Portal", "Application", "10.0.3.15", None, 1, "Human Resources", "Cloud", "High", "Active"),
    ("Core Switch", "Network Device", "10.0.0.1", "Cisco IOS", 1, "IT Security", "Data Center A", "High", "Under Maintenance"),
    ("S3 Backup Bucket", "Cloud Resource", "52.95.110.1", None, 1, "IT Security", "AWS eu-west-1", "Low", "Inactive"),
]

INCIDENTS = [
    ("Ransomware on web server", "Files on the main web server were encrypted.", "Malware Infection", "Critical", 1, 1),
    ("Phishing email to finance", "Employee received a fake invoice email with a malicious link.", "Phishing Attack", "Medium", 4, 2),
    ("Suspicious DB login", "Repeated failed logins on the customer database from an unknown IP.", "Unauthorized Access", "High", 1, 3),
    ("Unknown USB device", "A USB stick was found plugged into a workstation.", "Other", "Low", 4, 2),
]


def seed():
    if "--reset" in sys.argv and os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()
    conn = connect_to_db()
    try:
        if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            print("Database already has data. Run 'python seed.py --reset' to start fresh.")
            return
        conn.executemany(
            "INSERT INTO users (full_name, username, email, password_hash, department, role, account_status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(n, u, e, generate_password_hash(p), d, r, s) for n, u, e, p, d, r, s in USERS])
        conn.executemany(
            "INSERT INTO assets (asset_name, asset_type, ip_address, operating_system, owner_id, department, "
            "location, criticality_level, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", ASSETS)
        conn.executemany(
            "INSERT INTO incidents (title, description, category, severity, reporter_id, asset_id) "
            "VALUES (?, ?, ?, ?, ?, ?)", INCIDENTS)
        conn.commit()
        print(f"Seeded {len(USERS)} users, {len(ASSETS)} assets, {len(INCIDENTS)} incidents into {DB_PATH}")
    finally:
        conn.close()


if __name__ == "__main__":
    seed()
