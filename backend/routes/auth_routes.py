import datetime
import jwt
from flask import Blueprint, request, jsonify
from core.database import get_user_by_username, get_user_by_id, verify_password, create_user, get_all_users, update_user_password, delete_user, update_user_role, update_user_status, update_username

auth_bp = Blueprint('auth_routes', __name__)
SECRET_KEY = "antigravity_secret_key" # In production, use environment variable

def generate_token(user_id, username, role):
    payload = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def decode_token(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except:
        return None

@auth_bp.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    
    user = get_user_by_username(username)
    if user and verify_password(password, user["password_hash"]):
        token = generate_token(user["id"], user["username"], user["role"])
        return jsonify({
            "ok": True,
            "token": token,
            "user": {"username": user["username"], "role": user["role"]}
        })
    
    return jsonify({"ok": False, "message": "اسم المستخدم أو كلمة المرور غير صحيحة"}), 401

@auth_bp.route("/auth/me", methods=["GET"])
def get_me():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"ok": False}), 401
    
    token = auth_header.split(" ")[1]
    payload = decode_token(token)
    if payload:
        return jsonify({"ok": True, "user": payload})
    return jsonify({"ok": False}), 401

@auth_bp.route("/auth/users", methods=["GET"])
def list_users():
    # Basic check - should be admin
    users = get_all_users()
    return jsonify({"ok": True, "users": users})

@auth_bp.route("/auth/users", methods=["POST"])
def add_user():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "user")
    
    if create_user(username, password, role):
        return jsonify({"ok": True, "message": "تم إنشاء المستخدم بنجاح"})
    return jsonify({"ok": False, "message": "اسم المستخدم موجود مسبقاً"}), 400

@auth_bp.route("/auth/users/<int:user_id>", methods=["DELETE"])
def remove_user(user_id):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"ok": False, "message": "Unauthorized"}), 401
    
    token = auth_header.split(" ")[1]
    payload = decode_token(token)
    if not payload or payload.get("role") != "admin":
        return jsonify({"ok": False, "message": "Admin privileges required"}), 403
    
    if payload.get("user_id") == user_id:
        return jsonify({"ok": False, "message": "لا يمكنك حذف حسابك الحالي"}), 400
        
    delete_user(user_id)
    return jsonify({"ok": True, "message": "تم حذف المستخدم بنجاح"})

@auth_bp.route("/auth/users/password", methods=["PUT"])
def change_password():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"ok": False, "message": "Unauthorized"}), 401
    
    token = auth_header.split(" ")[1]
    payload = decode_token(token)
    if not payload:
        return jsonify({"ok": False, "message": "Invalid token"}), 401
        
    data = request.get_json()
    old_password = data.get("old_password")
    new_password = data.get("new_password")
    
    if not old_password or not new_password:
        return jsonify({"ok": False, "message": "Missing passwords"}), 400
        
    user_id = payload.get("user_id")
    user = get_user_by_id(user_id)
    
    if not user or not verify_password(old_password, user["password_hash"]):
        return jsonify({"ok": False, "message": "كلمة المرور الحالية غير صحيحة"}), 400
        
    update_user_password(user_id, new_password)
    return jsonify({"ok": True, "message": "تم تحديث كلمة المرور بنجاح"})

@auth_bp.route("/auth/users/<int:target_id>/role", methods=["PUT"])
def change_user_role(target_id):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"ok": False, "message": "Unauthorized"}), 401
    
    token = auth_header.split(" ")[1]
    payload = decode_token(token)
    if not payload or payload.get("role") != "admin":
        return jsonify({"ok": False, "message": "Admin privileges required"}), 403
        
    data = request.get_json()
    new_role = data.get("role")
    if new_role not in ["admin", "user"]:
        return jsonify({"ok": False, "message": "Invalid role"}), 400
        
    if payload.get("user_id") == target_id:
        return jsonify({"ok": False, "message": "لا يمكنك تغيير صلاحياتك بنفسك"}), 400
        
    update_user_role(target_id, new_role)
    return jsonify({"ok": True, "message": "تم تحديث الصلاحيات بنجاح"})

@auth_bp.route("/auth/users/<int:target_id>/status", methods=["PUT"])
def toggle_status(target_id):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"ok": False, "message": "Unauthorized"}), 401
    
    token = auth_header.split(" ")[1]
    payload = decode_token(token)
    if not payload or payload.get("role") != "admin":
        return jsonify({"ok": False, "message": "Admin privileges required"}), 403
        
    data = request.get_json()
    new_status = data.get("status")
    if new_status not in ["active", "suspended"]:
        return jsonify({"ok": False, "message": "Invalid status"}), 400
        
    if payload.get("user_id") == target_id:
        return jsonify({"ok": False, "message": "لا يمكنك إيقاف حسابك بنفسك"}), 400
        
    update_user_status(target_id, new_status)
    return jsonify({"ok": True, "message": "تم تحديث حالة الحساب بنجاح"})

@auth_bp.route("/auth/users/<int:target_id>/admin_password", methods=["PUT"])
def admin_reset_password(target_id):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"ok": False, "message": "Unauthorized"}), 401
    
    token = auth_header.split(" ")[1]
    payload = decode_token(token)
    if not payload or payload.get("role") != "admin":
        return jsonify({"ok": False, "message": "Admin privileges required"}), 403
        
    data = request.get_json()
    new_password = data.get("new_password")
    
    if not new_password:
        return jsonify({"ok": False, "message": "Missing password"}), 400
        
    update_user_password(target_id, new_password)
    return jsonify({"ok": True, "message": "تم إعادة تعيين كلمة المرور بنجاح"})

@auth_bp.route("/auth/users/<int:target_id>/username", methods=["PUT"])
def change_username(target_id):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"ok": False, "message": "Unauthorized"}), 401
    
    token = auth_header.split(" ")[1]
    payload = decode_token(token)
    if not payload or payload.get("role") != "admin":
        return jsonify({"ok": False, "message": "Admin privileges required"}), 403
        
    data = request.get_json()
    new_username = data.get("username", "").strip()
    
    if not new_username:
        return jsonify({"ok": False, "message": "Missing username"}), 400
        
    if update_username(target_id, new_username):
        return jsonify({"ok": True, "message": "تم تحديث اسم المستخدم بنجاح"})
    else:
        return jsonify({"ok": False, "message": "اسم المستخدم موجود مسبقاً"}), 400
