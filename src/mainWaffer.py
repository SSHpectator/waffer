import requests
from typing import Optional, Dict
import re

WAF_FINGERPRINTS = {
    "Cloudflare": {
        "headers": [r"server:\s*cloudflare", r"cf-ray", r"cf-edge-cache"],
        "cookies": [r"__cfduid", r"__cf_bm"],
        "body": [r"Attention Required!|checking your browser|Cloudflare"],
        "status_codes": []
    },
    "Akamai": {
        "headers": [r"server:\s*akamai", r"x-akamai-transformed"],
        "cookies": [r"aka_debug", r"akamai"],
        "body": [r"Reference ID: "],
        "status_codes": []
    },
    "AWS WAF / ALB": {
        "headers": [r"server:\s*awselb", r"via: .*cloudfront"],
        "cookies": [],
        "body": [r"blocked by AWS WAF", r"AWS WAF"],
        "status_codes": []
    },
    "ModSecurity": {
        "headers": [r"mod_security", r"mod_security2", r"mod_security_nginx"],
        "cookies": [],
        "body": [r"Mod_Security|Access denied with code 403"],
        "status_codes": []
    },
    "F5 BIG-IP ASM": {
        "headers": [r"BIGipServer", r"X-F5-"],
        "cookies": [r"TS[0-9a-zA-Z_-]{6,}"],  # example: TSxxxx
        "body": [r"Access Denied - F5"],
        "status_codes": []
    },
}


class WafDetector:
    def __init__(self, timeout: float = 10.0, user_agent: Optional[str] = None):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": user_agent
        })

    def _fetch(self, url: str, method: str = "HEAD", params: Dict[str, str] = None) -> Optional[requests.Response]:
        try:
            if method.upper() == "HEAD":
                return self.session.head(url, timeout=self.timeout, allow_redirects=True)
            else:
                return self.session.get(url, timeout=self.timeout, params=params, allow_redirects=True)
        except requests.RequestException:
            return None
    
    """
    Detect headers, cookie ecct of WAFs
    """
    def detect(self, url: str) -> Dict[str, any]:

        result = {
            "url": url,
            "found": [],
            "baseline_status": None,
            "baseline_headers": None,
            "error": None
        }

        "Fetch baseline"
        resp = self._fetch(url)
        if resp is None:
            result["error"] = "no_response"
            return result
        
        result["baseline_status"] = resp.status_code
        result["baseline_headers"] = dict(resp.headers)

        """
        passive matching
        If waf_name item is == WAF_FINGERPRINTS.item() we have a match
        """
        for waf_name, fp in WAF_FINGERPRINTS.items():
            matches = []

            # Headers first
            headers_concat = "\n".join(f"{k}: {v}" for k,v in resp.headers.items()).lower()

            for hpat in fp.get("headers", []):
                try:
                    if re.search(hpat, headers_concat, re.I):
                        matches.append({"type": "header", "pattern": hpat})
                    else:
                        pass
                except re.error:
                    pass
            
            # Cookies
            cookies_concat = "\n".join(f"{k}: {v}" for k,v in resp.headers.items()).lower()

            for cpat in fp.get("cookies", []):
                try:
                    if re.search(cpat, cookies_concat, re.I):
                        matches.append({"type": "cookie", "pattern": cpat})
                    else:
                        pass
                except re.error:
                    pass
            
            # Body
            body_con = (resp.text or "")

            for bpat in fp.get("body", []):
                try:
                    if re.search(bpat, body_con, re.I):
                        matches.append({"type": "body", "pattern": bpat})
                    else:
                        pass
                except re.error:
                    pass
            
            # Status code
            codes = fp.get("status_codes", [])
            if codes and resp.status_code in codes:
                matches.append({"type": "status_code", "pattern": str(resp.status_code)})
            
            if matches:
                score = min(100, 30+20*len(matches)) # +20 per match
                result["found"].append({
                    "waf": waf_name,
                    "matches": matches,
                    "score": score,
                    "method": "passive"
                })
        
        # sort by decreasing score
        result["found"].sort(key=lambda x: x.get("score", 0), reverse=True)
        return result

import argparse
def main():
    parser = argparse.ArgumentParser(description="WAF Detector")
    parser.add_argument("url", help="URL target (include scheme e.g. https://example.com)")
    parser.add_argument("--active", action="store_true", help="Esegui test attivo (rischio legale: usa con permesso)")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    detector = WafDetector(timeout=args.timeout)
    res = detector.detect(args.url)
    import json
    print(json.dumps(res, indent=2, ensure_ascii=False))

if __name__ == "__main__":

    main()

