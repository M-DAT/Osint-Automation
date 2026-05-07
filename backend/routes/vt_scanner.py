import os
from flask import Blueprint, request, jsonify
from core.config import VT_API_KEYS_FILE
from services.vt_service import normalize_items, vt_scan_item, HASH_REGEX, IP_REGEX, DOMAIN_REGEX

vt_bp = Blueprint('vt_scanner', __name__)

@vt_bp.route("/parse_hashes", methods=["POST"])
def parse_hashes():
    data = request.get_json()
    hashes_text = data.get("hashes", "")
    items = normalize_items(hashes_text)

    return jsonify({
        "ok": True,
        "hashes": items,
        "count": len(items)
    })

@vt_bp.route("/get_api_keys", methods=["GET"])
def get_api_keys():
    keys = []
    if os.path.exists(VT_API_KEYS_FILE):
        with open(VT_API_KEYS_FILE, "r") as f:
            for line in f:
                k = line.strip()
                if k:
                    keys.append(k)
    return jsonify({"ok": True, "keys": keys})

@vt_bp.route("/add_api_key", methods=["POST"])
def add_api_key():
    data = request.get_json()
    new_key = data.get("api_key", "").strip()
    
    if not new_key:
        return jsonify({"ok": False, "message": "المفتاح فارغ"}), 400
        
    keys = []
    if os.path.exists(VT_API_KEYS_FILE):
        with open(VT_API_KEYS_FILE, "r") as f:
            keys = [line.strip() for line in f if line.strip()]
            
    if new_key in keys:
        return jsonify({"ok": True, "message": "المفتاح موجود مسبقاً", "keys": keys})
        
    with open(VT_API_KEYS_FILE, "a") as f:
        f.write(new_key + "\n")
        
    keys.append(new_key)
    return jsonify({"ok": True, "message": "تمت إضافة المفتاح", "keys": keys})

@vt_bp.route("/scan_one", methods=["POST"])
def scan_one():
    data = request.get_json()

    api_key = data.get("api_key", "").strip()
    item = data.get("hash", "").strip().lower()

    if not api_key:
        return jsonify({
            "ok": False,
            "message": "API Key مفقود"
        }), 400

    if not (HASH_REGEX.match(item) or IP_REGEX.match(item) or DOMAIN_REGEX.match(item)):
        return jsonify({
            "ok": False,
            "message": "عنصر غير صحيح"
        }), 400

    result = vt_scan_item(api_key, item)

    return jsonify({
        "ok": True,
        "result": result
    })
