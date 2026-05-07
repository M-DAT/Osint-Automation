import re
import requests

HASH_REGEX = re.compile(
    r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$"
)

IP_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

def normalize_items(raw_text: str):
    items = re.split(r"[\s,;]+", raw_text.strip())
    valid_items = []

    for item in items:
        h = item.strip()
        if not h:
            continue
        h_lower = h.lower()
        if HASH_REGEX.match(h_lower) or IP_REGEX.match(h_lower) or DOMAIN_REGEX.match(h_lower):
            valid_items.append(h_lower)

    return list(dict.fromkeys(valid_items))


def vt_scan_item(api_key: str, item: str):
    headers = {"x-apikey": api_key}
    
    if HASH_REGEX.match(item):
        url = f"https://www.virustotal.com/api/v3/files/{item}"
        item_type = "hash"
        gui_url = f"https://www.virustotal.com/gui/file/{item}"
    elif IP_REGEX.match(item):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{item}"
        item_type = "ip"
        gui_url = f"https://www.virustotal.com/gui/ip-address/{item}"
    elif DOMAIN_REGEX.match(item):
        url = f"https://www.virustotal.com/api/v3/domains/{item}"
        item_type = "domain"
        gui_url = f"https://www.virustotal.com/gui/domain/{item}"
    else:
        return {
           "hash": item,
           "status": "error",
           "label": "خطأ",
           "malicious": "-",
           "suspicious": "-",
           "harmless": "-",
           "undetected": "-",
           "file_name": "-",
           "description": "عنصر غير مدعوم",
           "vt_url": "-"
        }

    try:
        response = requests.get(url, headers=headers, timeout=25)

        if response.status_code == 404:
            return {
                "hash": item,
                "status": "not_found",
                "label": "غير موجود",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "file_name": "-",
                "description": "العنصر غير موجود في VirusTotal",
                "vt_url": gui_url
            }

        if response.status_code == 401:
            return {
                "hash": item,
                "status": "error",
                "label": "خطأ",
                "malicious": "-",
                "suspicious": "-",
                "harmless": "-",
                "undetected": "-",
                "file_name": "-",
                "description": "API Key غير صحيح",
                "vt_url": "-"
            }

        if response.status_code == 429:
            return {
                "hash": item,
                "status": "error",
                "label": "Rate Limit",
                "malicious": "-",
                "suspicious": "-",
                "harmless": "-",
                "undetected": "-",
                "file_name": "-",
                "description": "تم تجاوز حد الطلبات. ارفع قيمة Delay",
                "vt_url": "-"
            }

        response.raise_for_status()

        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        file_name = "-"
        if item_type == "hash":
            names = attributes.get("names", [])
            file_name = names[0] if names else "-"
        elif item_type == "ip":
            as_owner = attributes.get("as_owner", "")
            network = attributes.get("network", "")
            if as_owner:
                file_name = as_owner
            elif network:
                file_name = network
        elif item_type == "domain":
            registrar = attributes.get("registrar", "")
            if registrar:
                file_name = registrar

        if malicious > 0:
            status = "malicious"
            label = "خطير"
        elif suspicious > 0:
            status = "suspicious"
            label = "مشبوه"
        else:
            status = "clean"
            label = "نظيف"

        return {
            "hash": item,
            "status": status,
            "label": label,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "file_name": file_name,
            "description": f"Malicious: {malicious}, Suspicious: {suspicious}, Harmless: {harmless}",
            "vt_url": gui_url
        }

    except requests.exceptions.Timeout:
        return {
            "hash": item,
            "status": "error",
            "label": "Timeout",
            "malicious": "-",
            "suspicious": "-",
            "harmless": "-",
            "undetected": "-",
            "file_name": "-",
            "description": "انتهت مهلة الاتصال مع VirusTotal",
            "vt_url": "-"
        }

    except requests.exceptions.RequestException as e:
        return {
            "hash": item,
            "status": "error",
            "label": "خطأ",
            "malicious": "-",
            "suspicious": "-",
            "harmless": "-",
            "undetected": "-",
            "file_name": "-",
            "description": str(e),
            "vt_url": "-"
        }
