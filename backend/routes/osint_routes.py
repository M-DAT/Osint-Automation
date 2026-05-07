import os
from flask import Blueprint, request, jsonify
from core.database import get_osint_keys, add_osint_key
from core.config import VT_API_KEYS_FILE
from services.vt_service import IP_REGEX, DOMAIN_REGEX
from services.osint_service import fetch_ipinfo, fetch_abuseipdb_ip, fetch_vt_ip, gather_domain_osint
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from hibp_scraper import check_hibp
osint_bp = Blueprint('osint_routes', __name__)

# All supported OSINT services
OSINT_SERVICES = ['whoisfreaks', 'dnsdumpster', 'ipinfo', 'urlscan', 'abuseipdb']

@osint_bp.route("/osint/api_keys", methods=["GET"])
def osint_get_keys():
    keys = get_osint_keys()
    status = {}
    for svc in OSINT_SERVICES:
        status[svc] = len(keys.get(svc, []))
    
    # Also count VT keys from the scanner's file
    vt_count = 0
    if os.path.exists(VT_API_KEYS_FILE):
        with open(VT_API_KEYS_FILE, "r") as f:
            vt_count = len([l for l in f if l.strip()])
    status["virustotal"] = vt_count
    
    return jsonify({"ok": True, "keys_status": status})

@osint_bp.route("/osint/api_keys", methods=["POST"])
def osint_save_keys():
    data = request.get_json()
    for svc in OSINT_SERVICES:
        add_osint_key(svc, data.get(svc))
    return jsonify({"ok": True, "message": "تمت إضافة المفاتيح بنجاح"})

@osint_bp.route("/osint/scan", methods=["POST"])
def osint_scan():
    data = request.get_json()
    target = data.get("target", "").strip().lower()
    
    if not target:
        return jsonify({"ok": False, "message": "الهدف مفقود"}), 400
        
    keys = get_osint_keys()
    
    # Load VT keys from scanner's file for Passive DNS
    vt_keys = []
    if os.path.exists(VT_API_KEYS_FILE):
        with open(VT_API_KEYS_FILE, "r") as f:
            vt_keys = [l.strip() for l in f if l.strip()]
    keys["virustotal"] = vt_keys
    
    result = {"target": target, "type": "unknown"}
    
    if IP_REGEX.match(target):
        result["type"] = "ip"
        ipinfo_keys = keys.get("ipinfo", [])
        result["ipinfo"] = fetch_ipinfo(target, ipinfo_keys)
        abuseipdb_keys = keys.get("abuseipdb", [])
        result["abuseipdb"] = fetch_abuseipdb_ip(target, abuseipdb_keys)
        vt_keys = keys.get("virustotal", [])
        result["virustotal"] = fetch_vt_ip(target, vt_keys)
            
    elif DOMAIN_REGEX.match(target):
        result["type"] = "domain"
        domain_data = gather_domain_osint(target, keys)
        result.update(domain_data)
            
    else:
        return jsonify({"ok": False, "message": "الهدف ليس IP أو Domain صالح"}), 400
        
    return jsonify({"ok": True, "data": result})

@osint_bp.route("/osint/hibp", methods=["POST"])
def osint_hibp():
    data = request.get_json()
    target = data.get("target", "").strip()
    check_type = data.get("type", "email") # "email" or "password"
    
    if not target:
        return jsonify({"ok": False, "message": "Target missing"}), 400
        
    try:
        res = check_hibp(target, check_type)
        return jsonify(res)
    except Exception as e:
        return jsonify({"ok": False, "message": str(e)}), 500
