# Service 8: Notification and Alert Management Service
# Omar Obeid
from flask import Blueprint, g, request

from common import (ADMIN, ANALYST, AUDITOR, REGULAR, ApiError, deny, get_json_body, require_roles, set_developer,
                    success, write_log)
from models import Notification, NotificationRepository, UserRepository
from validators import (check_choice, check_int, check_string, clean_str, raise_if_errors, reject_unknown_fields,
                        require_fields)

DEVELOPER = "Omar Obeid"
SERVICE = "Notification and Alert Management"
CREATE_FIELDS = ["user_id", "title", "message", "notification_type", "severity_level"]
SEE_ALL_ROLES = (ADMIN, AUDITOR)  # everyone else only sees their own notifications

notifications_bp = Blueprint("notifications", __name__)
set_developer(notifications_bp, DEVELOPER)
notifications = NotificationRepository()
users = UserRepository()


def send_notification(user_id, title, message, notification_type, severity):
    """Used by other services (vulnerabilities, playbooks) to alert a user. (Omar Obeid)"""
    return notifications.insert({"user_id": user_id, "title": title, "message": message,
                                 "notification_type": notification_type, "severity_level": severity})


def _get_notification_or_404(notification_id):
    notification = notifications.get_by_id(notification_id)
    if notification is None:
        raise ApiError(f"Notification with id {notification_id} not found", 404)
    return notification


def _check_owner(notification, message):
    caller = g.current_user
    if caller["role"] not in SEE_ALL_ROLES and notification.user_id != caller["user_id"]:
        deny(message, SERVICE)


def _present(notification):
    data = notification.to_dict()
    user = users.get_by_id(notification.user_id)
    data["username"] = user.username if user else None
    return data


# ---------------------------------------------------------------- 1. Create Notification (Omar Obeid)
@notifications_bp.route("/notifications", methods=["POST"])
@require_roles(ADMIN, ANALYST, service=SERVICE)
def create_notification():
    data = get_json_body()
    reject_unknown_fields(data, CREATE_FIELDS)
    require_fields(data, CREATE_FIELDS)

    errors = {}
    check_int(errors, data, "user_id")
    check_string(errors, data, "title", 150)
    check_string(errors, data, "message", 2000)
    check_choice(errors, data, "notification_type", Notification.TYPES)
    check_choice(errors, data, "severity_level", Notification.SEVERITIES)
    raise_if_errors(errors)

    recipient = users.get_by_id(data["user_id"])
    if recipient is None:
        raise ApiError(f"Recipient user with id {data['user_id']} does not exist", 404)
    if recipient.account_status != "Active":
        raise ApiError(f"Cannot notify '{recipient.username}': account is {recipient.account_status}", 400)

    notification = send_notification(recipient.user_id, clean_str(data["title"]), clean_str(data["message"]),
                                     data["notification_type"], data["severity_level"])
    write_log(g.current_user["user_id"], "NOTIFICATION_CREATED",
              f"Notification {notification.notification_id} ({notification.notification_type}, "
              f"{notification.severity_level}) sent to '{recipient.username}'",
              "Warning" if notification.severity_level == "Critical" else "Information", SERVICE)
    return success("Notification created successfully", _present(notification), 201)


# ---------------------------------------------------------------- 2. Retrieve User Notifications (Omar Obeid)
@notifications_bp.route("/notifications/user/<int:user_id>", methods=["GET"])
@require_roles(ADMIN, ANALYST, AUDITOR, REGULAR, service=SERVICE)
def get_user_notifications(user_id):
    caller = g.current_user
    if caller["role"] not in SEE_ALL_ROLES and user_id != caller["user_id"]:
        deny("You can only view your own notifications", SERVICE)
    user = users.get_by_id(user_id)
    if user is None:
        raise ApiError(f"User with id {user_id} not found", 404)

    items = [n.to_dict() for n in notifications.for_user(user_id)]
    unread = sum(1 for n in items if n["status"] == "Unread")
    message = (f"{len(items)} notification(s) for '{user.username}' ({unread} unread)" if items
               else f"User '{user.username}' has no notifications")
    return success(message, {"user": {"user_id": user.user_id, "username": user.username, "role": user.role},
                             "count": len(items), "unread_count": unread, "notifications": items})


# ---------------------------------------------------------------- 5. Search Notifications (Omar Obeid)
@notifications_bp.route("/notifications/search", methods=["GET"])
@require_roles(ADMIN, ANALYST, AUDITOR, REGULAR, service=SERVICE)
def search_notifications():
    allowed = ["user", "type", "severity", "status"]
    unknown = sorted(set(request.args) - set(allowed))
    if unknown:
        raise ApiError("Unknown search parameters", 400,
                       {p: f"Allowed parameters: {', '.join(allowed)}" for p in unknown})
    if not request.args:
        raise ApiError(f"Provide at least one search parameter: {', '.join(allowed)}", 400)

    errors = {}
    check_choice(errors, request.args, "type", Notification.TYPES)
    check_choice(errors, request.args, "severity", Notification.SEVERITIES)
    check_choice(errors, request.args, "status", Notification.STATUSES)
    user = request.args.get("user", "").strip()
    if "user" in request.args and not user:
        errors["user"] = "Cannot be empty"
    raise_if_errors(errors)

    user_id, username = (int(user), None) if user.isdigit() else (None, user or None)
    caller = g.current_user
    if caller["role"] not in SEE_ALL_ROLES:
        # other roles search inside their own inbox only
        if user and user_id != caller["user_id"] and (username or "").lower() != caller["username"].lower():
            deny("You can only search your own notifications", SERVICE)
        user_id, username = caller["user_id"], None

    results = [_present(n) for n in notifications.filter(user_id, username, request.args.get("type"),
                                                         request.args.get("severity"), request.args.get("status"))]
    return success(f"{len(results)} notification(s) match the search",
                   {"criteria": dict(request.args), "count": len(results), "notifications": results})


# ---------------------------------------------------------------- 3. Retrieve Specific Notification (Omar Obeid)
@notifications_bp.route("/notifications/<int:notification_id>", methods=["GET"])
@require_roles(ADMIN, ANALYST, AUDITOR, REGULAR, service=SERVICE)
def get_notification(notification_id):
    notification = _get_notification_or_404(notification_id)
    _check_owner(notification, "You can only view your own notifications")
    return success("Notification found", _present(notification))


# ---------------------------------------------------------------- 4. Mark Notification as Read (Omar Obeid)
@notifications_bp.route("/notifications/<int:notification_id>/read", methods=["PUT"])
@require_roles(ADMIN, ANALYST, REGULAR, service=SERVICE)
def mark_notification_read(notification_id):
    notification = _get_notification_or_404(notification_id)
    if notification.user_id != g.current_user["user_id"] and g.current_user["role"] != ADMIN:
        deny("You can only mark your own notifications as read", SERVICE)
    if notification.status == "Read":
        return success(f"Notification was already read on {notification.read_date}", _present(notification))

    updated = notifications.mark_read(notification_id)
    write_log(g.current_user["user_id"], "NOTIFICATION_READ",
              f"Notification {notification_id} marked as read", "Information", SERVICE)
    return success("Notification marked as read", _present(updated))


# ---------------------------------------------------------------- 6. Delete Notification (Omar Obeid)
@notifications_bp.route("/notifications/<int:notification_id>", methods=["DELETE"])
@require_roles(ADMIN, service=SERVICE)
def delete_notification(notification_id):
    notification = _get_notification_or_404(notification_id)
    notifications.delete(notification_id)
    write_log(g.current_user["user_id"], "NOTIFICATION_DELETED",
              f"Notification {notification_id} '{notification.title}' (user id {notification.user_id}) deleted",
              "Warning", SERVICE)
    return success(f"Notification {notification_id} deleted successfully",
                   {"deleted_notification_id": notification_id, "deleted_notification": notification.to_dict()})
