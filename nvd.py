import json, time, pathlib, hashlib, requests, os

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE = pathlib.Path(".cache_nvd"); CACHE.mkdir(exist_ok=True)

# Optional NVD API key for higher rate limits
NVD_API_KEY = os.getenv("NVD_API_KEY")

def _p(cve_id: str) -> pathlib.Path:
    return CACHE / f"{cve_id}_{hashlib.sha1(cve_id.encode()).hexdigest()[:8]}.json"

def fetch_cve(cve_id: str) -> dict:
    p = _p(cve_id)
    if p.exists() and time.time() - p.stat().st_mtime < 7*24*3600:
        return json.loads(p.read_text(encoding="utf-8"))
    
    # Prepare headers with optional API key
    headers = {"User-Agent": "IncidentResponse-Phase1/1.0"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    
    try:
        r = requests.get(API, params={"cveId": cve_id}, headers=headers, timeout=15)
        r.raise_for_status()
        data = r.json()
        p.write_text(json.dumps(data), encoding="utf-8")
        return data
    except requests.exceptions.RequestException as e:
        # Graceful degradation - return minimal structure
        return {
            "vulnerabilities": [],
            "error": f"NVD API unavailable: {str(e)}",
            "cached": False
        }

def mitre_url(cve_id: str) -> str:
    return f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id.upper()}"