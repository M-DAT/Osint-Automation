import requests
import concurrent.futures
import itertools
import re

# ============================================================
# Helper: try multiple API keys with automatic fallback
# ============================================================
def _try_keys(api_keys, fetch_fn):
    """Try fetch_fn with each key until success or all exhausted."""
    if not api_keys:
        return {"error": "API Key مفقود"}
    last_error = "Unknown error"
    for key in api_keys:
        try:
            result = fetch_fn(key)
            if result is not None:
                return result
        except Exception as e:
            last_error = str(e)
            continue
    return {"error": last_error}


# ============================================================
# Step 1.1: WHOIS الأساسي (WhoisFreaks)
# ============================================================
def fetch_whois(domain: str, api_keys: list):
    def _fetch(key):
        r = requests.get(
            f"https://api.whoisfreaks.com/v1.0/whois?apiKey={key}&whois=live&domainName={domain}",
            timeout=15
        )
        if r.status_code == 200:
            return r.json()
        elif r.status_code in [429, 403, 401]:
            return None  # try next key
        return {"error": f"HTTP {r.status_code}"}
    return _try_keys(api_keys, _fetch)


# ============================================================
# Step 1.2: WHOIS التاريخي (WhoisFreaks Historical)
# ============================================================
def fetch_whois_historical(domain: str, api_keys: list):
    def _fetch(key):
        r = requests.get(
            f"https://api.whoisfreaks.com/v1.0/whois?apiKey={key}&whois=historical&domainName={domain}",
            timeout=20
        )
        if r.status_code == 200:
            data = r.json()
            records = data.get("whois_records", [])
            # Extract key historical changes
            history = []
            for rec in records[:10]:  # Limit to last 10 records
                history.append({
                    "create_date": rec.get("create_date", "-"),
                    "update_date": rec.get("update_date", "-"),
                    "expiry_date": rec.get("expiry_date", "-"),
                    "registrar": rec.get("registrar", {}).get("registrar_name", "-") if isinstance(rec.get("registrar"), dict) else rec.get("registrar_name", "-"),
                    "registrant_name": rec.get("registrant_contact", {}).get("name", "-") if isinstance(rec.get("registrant_contact"), dict) else "-",
                    "registrant_email": rec.get("registrant_contact", {}).get("email_address", "-") if isinstance(rec.get("registrant_contact"), dict) else "-",
                    "name_servers": rec.get("name_servers", []),
                })
            return {"records": history, "total": data.get("total_records", len(records))}
        elif r.status_code in [429, 403, 401]:
            return None
        return {"error": f"HTTP {r.status_code}"}
    return _try_keys(api_keys, _fetch)


# ============================================================
# Step 2: DNS Records (DNSDumpster)
# ============================================================
def fetch_dns(domain: str, api_keys: list):
    def _fetch(key):
        headers = {"X-API-Key": key}
        r = requests.get(f"https://api.dnsdumpster.com/domain/{domain}", headers=headers, timeout=20)
        if r.status_code == 200:
            return r.json()
        elif r.status_code in [429, 403, 401]:
            return None
        return {"error": f"HTTP {r.status_code}"}
    return _try_keys(api_keys, _fetch)


# ============================================================
# Step 3.1: Passive DNS via VirusTotal
# ============================================================
def fetch_passive_dns(domain: str, vt_api_keys: list):
    """Get historical DNS resolutions + full domain analysis from VirusTotal."""
    def _fetch(key):
        headers = {"x-apikey": key}
        result = {"resolutions": [], "total": 0, "vt_analysis": {}}
        
        # 1. Get resolutions (Passive DNS)
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions?limit=20",
                headers=headers, timeout=20
            )
            if r.status_code == 200:
                data = r.json()
                for item in data.get("data", []):
                    attrs = item.get("attributes", {})
                    result["resolutions"].append({
                        "ip": attrs.get("ip_address", "-"),
                        "date": attrs.get("date", 0),
                        "host_name": attrs.get("host_name", domain),
                        "resolver": attrs.get("host_name_last_analysis_stats", {})
                    })
                result["total"] = len(result["resolutions"])
            elif r.status_code in [429, 403, 401]:
                return None
        except:
            pass
        
        # 2. Get full domain analysis (reputation, categories, detections)
        try:
            r2 = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers=headers, timeout=20
            )
            if r2.status_code == 200:
                attrs = r2.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                result["vt_analysis"] = {
                    "reputation": attrs.get("reputation", 0),
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "categories": attrs.get("categories", {}),
                    "registrar": attrs.get("registrar", "-"),
                    "creation_date": attrs.get("creation_date", 0),
                    "last_analysis_date": attrs.get("last_analysis_date", 0),
                    "tags": attrs.get("tags", []),
                    "popularity_ranks": attrs.get("popularity_ranks", {}),
                    "total_votes": attrs.get("total_votes", {}),
                }
        except:
            pass
        
        return result
    return _try_keys(vt_api_keys, _fetch)


# ============================================================
# Step 4.1: Certificate Transparency Logs via crt.sh (FREE)
# ============================================================
def fetch_crtsh_subdomains(domain: str):
    """Query crt.sh for SSL certificate transparency logs - NO API KEY NEEDED."""
    try:
        r = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=30, headers={"User-Agent": "Mozilla/5.0"}
        )
        if r.status_code == 200:
            entries = r.json()
            # Extract unique subdomains
            subdomains = set()
            certs = []
            for entry in entries[:100]:  # Limit processing
                name_value = entry.get("name_value", "")
                issuer = entry.get("issuer_name", "-")
                not_before = entry.get("not_before", "-")
                not_after = entry.get("not_after", "-")
                
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    if name and name != domain and "*" not in name:
                        subdomains.add(name)
                
                certs.append({
                    "common_name": entry.get("common_name", "-"),
                    "name_value": name_value,
                    "issuer": issuer,
                    "not_before": not_before,
                    "not_after": not_after,
                    "serial": entry.get("serial_number", "-"),
                })
            
            return {
                "subdomains": sorted(list(subdomains)),
                "certificates": certs[:30],  # Limit to 30 certs
                "total_subdomains": len(subdomains),
                "total_certificates": len(entries)
            }
        return {"error": f"HTTP {r.status_code}", "subdomains": [], "certificates": []}
    except Exception as e:
        return {"error": str(e), "subdomains": [], "certificates": []}


# ============================================================
# Step 5.1: Typosquatting Analysis (LOCAL - No API needed)
# ============================================================
def generate_typosquatting(domain: str):
    """Generate potential typosquatting domains using multiple techniques."""
    # Split domain and TLD
    parts = domain.rsplit(".", 1)
    if len(parts) != 2:
        return {"variants": [], "error": "Invalid domain format"}
    
    name, tld = parts[0], parts[1]
    variants = []
    
    # 1. Character omission (حذف حرف)
    for i in range(len(name)):
        variant = name[:i] + name[i+1:]
        if variant:
            variants.append({"type": "حذف حرف", "domain": f"{variant}.{tld}", "technique": "Character Omission"})
    
    # 2. Adjacent character swap (تبديل حرفين متجاورين)
    for i in range(len(name) - 1):
        variant = list(name)
        variant[i], variant[i+1] = variant[i+1], variant[i]
        v = "".join(variant)
        if v != name:
            variants.append({"type": "تبديل حروف", "domain": f"{v}.{tld}", "technique": "Adjacent Swap"})
    
    # 3. Character replacement (استبدال حروف متشابهة)
    homoglyphs = {
        'a': ['4', '@'], 'b': ['d', '6'], 'c': ['k', 'e'],
        'e': ['3'], 'g': ['9', 'q'], 'i': ['1', 'l', '!'],
        'l': ['1', 'i', '|'], 'o': ['0'], 's': ['5', '$'],
        't': ['7', '+'], 'z': ['2']
    }
    for i, char in enumerate(name):
        for replacement in homoglyphs.get(char, []):
            variant = name[:i] + replacement + name[i+1:]
            variants.append({"type": "استبدال حروف متشابهة", "domain": f"{variant}.{tld}", "technique": "Homoglyph"})
    
    # 4. Character doubling (تكرار حرف)
    for i in range(len(name)):
        variant = name[:i] + name[i] + name[i:]
        if variant != name:
            variants.append({"type": "تكرار حرف", "domain": f"{variant}.{tld}", "technique": "Character Repeat"})
    
    # 5. Common TLD swap (تغيير الامتداد)
    alt_tlds = ['com', 'net', 'org', 'info', 'xyz', 'co', 'io', 'biz', 'online', 'site']
    for alt_tld in alt_tlds:
        if alt_tld != tld:
            variants.append({"type": "تغيير الامتداد", "domain": f"{name}.{alt_tld}", "technique": "TLD Swap"})
    
    # 6. Dot insertion (إدراج نقطة)
    for i in range(1, len(name)):
        variant = name[:i] + "." + name[i:]
        variants.append({"type": "إدراج نقطة", "domain": f"{variant}.{tld}", "technique": "Dot Insertion"})
    
    # Remove duplicates
    seen = set()
    unique = []
    for v in variants:
        if v["domain"] not in seen and v["domain"] != domain:
            seen.add(v["domain"])
            unique.append(v)
    
    return {"variants": unique[:50], "total": len(unique)}  # Limit to 50


# ============================================================
# Step 6.1: URLScan.io - Live Content Analysis
# ============================================================
def fetch_urlscan(domain: str, api_keys: list):
    """Search URLScan.io for existing scans of the domain."""
    def _fetch(key):
        headers = {"API-Key": key}
        # Search for existing scans first (faster than submitting new scan)
        r = requests.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=5",
            headers=headers, timeout=20
        )
        if r.status_code == 200:
            data = r.json()
            results = []
            for res in data.get("results", []):
                task = res.get("task", {})
                page = res.get("page", {})
                stats = res.get("stats", {})
                results.append({
                    "url": task.get("url", "-"),
                    "time": task.get("time", "-"),
                    "screenshot": res.get("screenshot", ""),
                    "report_url": res.get("result", ""),
                    "status": page.get("status", "-"),
                    "server": page.get("server", "-"),
                    "ip": page.get("ip", "-"),
                    "country": page.get("country", "-"),
                    "title": page.get("title", "-"),
                    "asn": page.get("asn", "-"),
                    "asnname": page.get("asnname", "-"),
                    "malicious": res.get("verdicts", {}).get("overall", {}).get("malicious", False),
                    "score": res.get("verdicts", {}).get("overall", {}).get("score", 0),
                    "tags": res.get("verdicts", {}).get("overall", {}).get("tags", []),
                })
            return {"scans": results, "total": data.get("total", 0)}
        elif r.status_code in [429, 403, 401]:
            return None
        return {"error": f"HTTP {r.status_code}"}
    
    if not api_keys:
        # URLScan search endpoint works without API key for public scans
        try:
            r = requests.get(
                f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=5",
                timeout=20
            )
            if r.status_code == 200:
                data = r.json()
                results = []
                for res in data.get("results", []):
                    task = res.get("task", {})
                    page = res.get("page", {})
                    results.append({
                        "url": task.get("url", "-"),
                        "time": task.get("time", "-"),
                        "screenshot": res.get("screenshot", ""),
                        "report_url": res.get("result", ""),
                        "status": page.get("status", "-"),
                        "server": page.get("server", "-"),
                        "ip": page.get("ip", "-"),
                        "country": page.get("country", "-"),
                        "title": page.get("title", "-"),
                        "asn": page.get("asn", "-"),
                        "asnname": page.get("asnname", "-"),
                        "malicious": res.get("verdicts", {}).get("overall", {}).get("malicious", False),
                        "score": res.get("verdicts", {}).get("overall", {}).get("score", 0),
                        "tags": res.get("verdicts", {}).get("overall", {}).get("tags", []),
                    })
                return {"scans": results, "total": data.get("total", 0)}
            return {"error": f"HTTP {r.status_code}", "scans": []}
        except Exception as e:
            return {"error": str(e), "scans": []}
    
    return _try_keys(api_keys, _fetch)


# ============================================================
# Step 1 (IP): IPInfo - معلومات IP
# ============================================================
def fetch_ipinfo(ip: str, api_keys: list):
    def _fetch(key):
        r = requests.get(f"https://ipinfo.io/{ip}?token={key}", timeout=15)
        if r.status_code == 200:
            return r.json()
        elif r.status_code in [429, 403, 401]:
            return None
        return {"error": f"HTTP {r.status_code}"}
    return _try_keys(api_keys, _fetch)


# ============================================================
# AbuseIPDB - فحص سمعة IP
# ============================================================
def fetch_abuseipdb_ip(ip: str, api_keys: list):
    """Check an IP address against AbuseIPDB for abuse reports."""
    def _fetch(key):
        headers = {
            "Key": key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": ""
        }
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers, params=params, timeout=15
        )
        if r.status_code == 200:
            data = r.json().get("data", {})
            return {
                "ipAddress": data.get("ipAddress", ip),
                "isPublic": data.get("isPublic", True),
                "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
                "countryCode": data.get("countryCode", "-"),
                "countryName": data.get("countryName", "-"),
                "usageType": data.get("usageType", "-"),
                "isp": data.get("isp", "-"),
                "domain": data.get("domain", "-"),
                "hostnames": data.get("hostnames", []),
                "isTor": data.get("isTor", False),
                "totalReports": data.get("totalReports", 0),
                "numDistinctUsers": data.get("numDistinctUsers", 0),
                "lastReportedAt": data.get("lastReportedAt", "-"),
                "isWhitelisted": data.get("isWhitelisted", False),
                "reports": [
                    {
                        "reportedAt": rpt.get("reportedAt", "-"),
                        "comment": rpt.get("comment", "-"),
                        "categories": rpt.get("categories", []),
                        "reporterCountryCode": rpt.get("reporterCountryCode", "-"),
                    }
                    for rpt in data.get("reports", [])[:15]
                ]
            }
        elif r.status_code in [429, 403, 401]:
            return None
        return {"error": f"HTTP {r.status_code}"}
    return _try_keys(api_keys, _fetch)


# ============================================================
# VirusTotal IP Analysis
# ============================================================
def fetch_vt_ip(ip: str, api_keys: list):
    """Get detailed IP analysis from VirusTotal."""
    def _fetch(key):
        headers = {"x-apikey": key}
        try:
            r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers, timeout=20)
            if r.status_code == 200:
                data = r.json().get("data", {})
                attrs = data.get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                return {
                    "reputation": attrs.get("reputation", 0),
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "as_owner": attrs.get("as_owner", "-"),
                    "asn": attrs.get("asn", "-"),
                    "country": attrs.get("country", "-"),
                    "tags": attrs.get("tags", []),
                    "whois": attrs.get("whois", "-"),
                    "last_analysis_date": attrs.get("last_analysis_date", 0)
                }
            elif r.status_code in [429, 403, 401]:
                return None
            return {"error": f"HTTP {r.status_code}"}
        except Exception as e:
            return {"error": str(e)}
    return _try_keys(api_keys, _fetch)


def fetch_abuseipdb_domain(domain: str, api_keys: list):
    """Check a domain by resolving it to IP then querying AbuseIPDB."""
    import socket
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        return {"error": "تعذر تحويل النطاق إلى IP", "resolved_ip": None}

    result = fetch_abuseipdb_ip(ip, api_keys)
    if isinstance(result, dict):
        result["resolved_ip"] = ip
        result["queried_domain"] = domain
    return result


# ============================================================
# Master: Gather ALL Domain OSINT (Parallel Execution)
# ============================================================
def gather_domain_osint(domain: str, keys: dict):
    """Run all OSINT steps in parallel for maximum speed."""
    whois_keys = keys.get("whoisfreaks", [])
    dns_keys = keys.get("dnsdumpster", [])
    vt_keys = keys.get("virustotal", [])
    urlscan_keys = keys.get("urlscan", [])
    abuseipdb_keys = keys.get("abuseipdb", [])
    
    result = {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = {
            executor.submit(fetch_whois, domain, whois_keys): "whois",
            executor.submit(fetch_whois_historical, domain, whois_keys): "whois_historical",
            executor.submit(fetch_dns, domain, dns_keys): "dns",
            executor.submit(fetch_passive_dns, domain, vt_keys): "passive_dns",
            executor.submit(fetch_crtsh_subdomains, domain): "crtsh",
            executor.submit(generate_typosquatting, domain): "typosquatting",
            executor.submit(fetch_urlscan, domain, urlscan_keys): "urlscan",
            executor.submit(fetch_abuseipdb_domain, domain, abuseipdb_keys): "abuseipdb",
        }
        
        for future in concurrent.futures.as_completed(futures):
            key = futures[future]
            try:
                result[key] = future.result()
            except Exception as e:
                result[key] = {"error": str(e)}
    
    return result
