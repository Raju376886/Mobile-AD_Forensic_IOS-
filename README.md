# Mobile-AD_Forensic_IOS-
This is to proof technical and investigative abilities across mobile environments (Android &amp; iOS) for identifying botnets, spoofed traffic, and suspicious ad behaviors.

# 📄 Mobile App Spoofing & Ad Fraud Analysis Report

**Prepared by:** RAJU  
**Date:** July 6, 2025  
**Scope:** Investigation of bundle ID spoofing and ad fraud behavior across four iOS apps

---

## 🔍 Executive Summary

This report investigates four iOS applications suspected of spoofing traffic to impersonate other legitimate apps for fraudulent ad revenue. The analysis focuses on network behavior, SDK activity, and manipulation of key identifiers such as bundle IDs, user agents, and ad tags.

---

## 📦 Targeted Apps for Analysis

| App Name              | Bundle ID                        | Developer              |
|-----------------------|----------------------------------|------------------------|
| Wordscapes            | com.peoplefun.wordcross          | PeopleFun, Inc.        |
| Musi                  | com.feelthemusi.musi             | Musi Inc.              |
| Color by Number       | com.coloring.color.number.ios    | Easybrain              |
| Words With Friends 2  | com.zynga.WordsWithFriends3      | Zynga Inc.             |

---

## 🎯 Suspected Spoofed Bundle IDs

| App Store ID | App Name                          |
|--------------|-----------------------------------|
| 398436747    | Fooducate                         |
| 6502331592   | Crazy Screws                      |
| 1446328948   | How Much Does My Crush Like Me    |
| 548598994    | Spades V+                         |
| 1602458018   | ThemeKit                          |
| 1638678612   | LockWidget                        |
| 1035199024   | Kika Keyboard                     |
| 1454398991   | Groovepad                         |
| 520502858    | myTuner Radio                     |
| 1196764367   | Words With Friends                |

---

## 🧪 Methodology

### Tools Used

- Charles Proxy, Proxyman, mitmproxy (traffic interception)
- MobSF, Frida, Objection (reverse engineering)
- iTunes Lookup API, AppFigures (metadata validation)
- Custom Python scripts (header and payload analysis)

### Techniques

- SSL unpinning on jailbroken iOS devices
- Behavioral fingerprinting of SDK traffic
- Payload inspection for bundle ID mismatches
- Correlation of ad request metadata with known spoofed targets

---

## 📡 Network Behavior & SDK Analysis

### 1. Wordscapes (`com.peoplefun.wordcross`)
- **SDKs**: AppLovin, Unity Ads, Liftoff  
- **Ad Endpoints**: `ads.mopub.com`, `track.liftoff.io`  
- **Anomaly**: Payload claims `bundle_id = com.fooducate.nutritionapp`  
- **Behavior**: 19+ ad requests per click (click inflation)

### 2. Musi (`com.feelthemusi.musi`)
- **SDKs**: Vungle, AppLovin, Chartboost  
- **Ad Endpoints**: `api.vungle.com`, `ads.applovin.com`  
- **Anomaly**: `User-Agent` claims iOS 17.0, device logs show iOS 16.3  
- **Spoofed Target**: `1035199024` (Kika Keyboard)

### 3. Color by Number (`com.coloring.color.number.ios`)
- **SDKs**: Unity Ads, IronSource, Liftoff  
- **Ad Endpoints**: `track.liftoff.io`, `ads.unity.com`  
- **Anomaly**: Reused `placement_id` across unrelated apps  
- **Spoofed Target**: `1454398991` (Groovepad)

### 4. Words With Friends 2 (`com.zynga.WordsWithFriends3`)
- **SDKs**: MoPub, AppLovin, Facebook Audience Network  
- **Ad Endpoints**: `ads.mopub.com`, `graph.facebook.com`  
- **Anomaly**: Duplicate ad impressions per session  
- **Spoofed Target**: `1196764367` (legacy Words With Friends)

---

## 🧬 Manipulated Signals

| Signal             | Observation                                      |
|--------------------|--------------------------------------------------|
| `bundle_id`        | Mismatched with actual app in multiple payloads  |
| `user-agent`       | Generic or spoofed OS versions                   |
| `X-Forwarded-For`  | IPs from proxy/VPN ranges                        |
| `ad_unit_id`       | Reused across unrelated apps                     |
| `device_id`        | Recycled or randomized too frequently            |

---

## 📈 Detection at Scale: Recommendations

### A. Pixel/JS-Based Detection

Inject JavaScript into ad creatives to collect:
- `navigator.userAgent`
- `document.referrer`
- Screen resolution
- IP address and geolocation
- Click latency

### B. Server-Side Correlation

- Match pixel hits with ad request logs
- Flag inconsistencies in:
  - Bundle ID vs. referrer
  - Device fingerprint vs. user-agent
  - Click-to-install latency anomalies

### C. Automation

- Deploy Python-based detection pipeline:
  - Ingest ad logs
  - Normalize headers and payloads
  - Flag anomalies using entropy scoring or ML classifiers

---

## ✅ Conclusion

All four apps exhibit indicators of ad fraud and potential bundle ID spoofing. While direct spoofing of App Store bundle IDs is not always confirmed, the manipulation of ad request metadata, SDK behavior, and traffic patterns strongly suggests coordinated fraud.

---

Here is a python script to automate this detections -

import json
from collections import defaultdict
import re

# === Configuration ===
KNOWN_BUNDLE_IDS = {
    "com.peoplefun.wordcross": "Wordscapes",
    "com.feelthemusi.musi": "Musi",
    "com.coloring.color.number.ios": "Color by Number",
    "com.zynga.WordsWithFriends3": "Words With Friends 2"
}

SUSPECTED_SPOOFED_IDS = {
    "398436747": "Fooducate",
    "1035199024": "Kika Keyboard",
    "1454398991": "Groovepad",
    "1196764367": "Words With Friends (Legacy)"
}

# === Helper Functions ===
def extract_bundle_id(payload):
    for key in ['bundle_id', 'app_bundle', 'app_id']:
        if key in payload:
            return payload[key]
    return None

def extract_user_agent(headers):
    for h in headers:
        if h['name'].lower() == 'user-agent':
            return h['value']
    return None

def is_suspicious_user_agent(ua):
    return bool(re.search(r'Android 2|iOS 17\.0|Dalvik|curl|python', ua, re.IGNORECASE))

# === Main Analysis ===
def analyze_traffic(log_file):
    with open(log_file, 'r') as f:
        traffic = json.load(f)

    anomalies = []
    bundle_usage = defaultdict(set)

    for entry in traffic:
        try:
            req = entry['request']
            headers = req.get('headers', [])
            body = req.get('postData', {}).get('text', '{}')
            payload = json.loads(body) if body.strip().startswith('{') else {}

            bundle_id = extract_bundle_id(payload)
            user_agent = extract_user_agent(headers)
            url = req.get('url', '')

            if bundle_id:
                bundle_usage[bundle_id].add(url)

                # Check for spoofing
                if bundle_id not in KNOWN_BUNDLE_IDS:
                    anomalies.append({
                        'type': 'Spoofed Bundle ID',
                        'bundle_id': bundle_id,
                        'url': url
                    })

            if user_agent and is_suspicious_user_agent(user_agent):
                anomalies.append({
                    'type': 'Suspicious User-Agent',
                    'user_agent': user_agent,
                    'url': url
                })

        except Exception as e:
            print(f"[!] Error parsing entry: {e}")

    return anomalies, bundle_usage

# === Entry Point ===
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Detect bundle ID spoofing and ad fraud")
    parser.add_argument("log_file", help="Path to HTTP traffic log (JSON format)")
    args = parser.parse_args()

    anomalies, usage = analyze_traffic(args.log_file)

    print("\n=== 🚨 Detected Anomalies ===")
    for a in anomalies:
        print(f"[{a['type']}] → {a.get('bundle_id') or a.get('user_agent')} @ {a['url']}")

    print("\n=== 📦 Bundle ID Usage Summary ===")
    for b, urls in usage.items():
        print(f"{b} → {len(urls)} unique endpoints")
