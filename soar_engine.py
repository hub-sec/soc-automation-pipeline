import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# ------------------------------------------------------------------
# CONFIGURATION: 
DISCORD_WEBHOOK_URL = "YOUR_DISCORD_WEBHOOK_URL"
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY"
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
# ------------------------------------------------------------------

def query_abuseipdb(ip):
    """Odpytuje AbuseIPDB API pod kątem reputacji IP"""
    if ABUSEIPDB_API_KEY == "TUTAJ_WKLEJ_KLUCZ_ABUSEIPDB":
        return {"score": 0, "country": "N/A", "reports": 0}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY
    }
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}

    try:
        res = requests.get(url, headers=headers, params=params, timeout=5)
        if res.status_code == 200:
            data = res.json().get('data', {})
            return {
                "score": data.get('abuseConfidenceScore', 0),
                "country": data.get('countryCode', 'N/A'),
                "reports": data.get('totalReports', 0),
                "isp": data.get('isp', 'N/A')
            }
    except Exception as e:
        print(f"[!] Błąd AbuseIPDB: {e}")

    return {"score": 0, "country": "N/A", "reports": 0}

def query_virustotal(file_hash):
    """Odpytuje VirusTotal API v3 pod kątem reputacji hasha"""
    if VIRUSTOTAL_API_KEY == "TUTAJ_WKLEJ_KLUCZ_VIRUSTOTAL" or not file_hash:
        return {"verdict": "UNKNOWN", "malicious_count": 0, "total_engines": 0}

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        res = requests.get(url, headers=headers, timeout=5)
        if res.status_code == 200:
            stats = res.json()['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values())

            if malicious > 3:
                verdict = "MALICIOUS"
            elif malicious > 0 or suspicious > 0:
                verdict = "SUSPICIOUS"
            else:
                verdict = "CLEAN"

            return {
                "verdict": verdict,
                "malicious_count": malicious,
                "total_engines": total
            }
        elif res.status_code == 404:
            return {"verdict": "NOT_FOUND", "malicious_count": 0, "total_engines": 0}
    except Exception as e:
        print(f"[!] Błąd VirusTotal: {e}")

    return {"verdict": "UNKNOWN", "malicious_count": 0, "total_engines": 0}

def send_discord_alert(rule_desc, hostname, src_ip, ip_intel, file_hash, hash_intel):
    """Wysyła sformatowaną kafelkę na Discorda na podstawie żywych danych API"""
    if DISCORD_WEBHOOK_URL == "TUTAJ_WKLEJ_SWOJ_URL_WEBHOOKA":
        return

    is_malicious = hash_intel.get("verdict") == "MALICIOUS" or ip_intel.get("score", 0) > 50
    color = 15158332 if is_malicious else 15844367  # Czerwony / Żółty

    payload = {
        "username": "SOAR Threat Bot",
        "avatar_url": "https://cdn-icons-png.flaticon.com/512/1022/1022313.png",
        "embeds": [{
            "title": f"🚨 [LIVE INTEL ALERT] {rule_desc}",
            "color": color,
            "fields": [
                {"name": "🖥️ Hostname", "value": f"`{hostname}`", "inline": True},
                {
                    "name": "🌐 Src IP (AbuseIPDB)", 
                    "value": f"`{src_ip}` ({ip_intel.get('country')})\n**Abuse Score:** {ip_intel.get('score')}% ({ip_intel.get('reports')} zgłoszeń)", 
                    "inline": True
                },
                {
                    "name": "🔑 File Hash (VirusTotal)", 
                    "value": f"`{file_hash[:20]}...`\n**Verdict:** {hash_intel.get('verdict')} ({hash_intel.get('malicious_count')}/{hash_intel.get('total_engines')} AVs)", 
                    "inline": False
                },
                {
                    "name": "💡 Recommended Action", 
                    "value": "🚨 **ISOLATE HOST IMMEDIATELY!**" if is_malicious else "⚠️ Monitor endpoint & user traffic.", 
                    "inline": False
                }
            ],
            "footer": {"text": "SOC Automation Pipeline v1.0 • Live API Enrichment"}
        }]
    }

    try:
        requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=3)
        print("🟢 Powiadomienie z żywym API wysłane na Discorda!")
    except Exception as e:
        print(f"🔴 Błąd Discorda: {e}")

@app.route('/webhook', methods=['POST'])
def receive_alert():
    alert_data = request.json
    if not alert_data:
        return jsonify({"status": "error"}), 400

    rule_desc = alert_data.get("description", "Unknown Alert")
    hostname = alert_data.get("hostname", "UNKNOWN-HOST")
    src_ip = alert_data.get("src_ip", "0.0.0.0")
    file_hash = alert_data.get("file_hash", "")

    # Odpytanie zewnętrznych API
    ip_intel = query_abuseipdb(src_ip) if src_ip else {}
    hash_intel = query_virustotal(file_hash) if file_hash else {}

    # Wysyłka alertu
    send_discord_alert(rule_desc, hostname, src_ip, ip_intel, file_hash, hash_intel)

    return jsonify({"status": "success"}), 200

if __name__ == '__main__':
    print("[+] SOAR Engine uruchomiony z żywym API (VirusTotal + AbuseIPDB)...")
    app.run(host='127.0.0.1', port=5000, debug=True)