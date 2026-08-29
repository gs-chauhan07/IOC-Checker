import os
import re
import json
import getpass
from datetime import datetime

import requests


# ==========================================
# CONFIGURATION
# ==========================================

CONFIG_FILE = os.path.expanduser(
    "~/.ioc_checker_config.json"
)

ALERT_FILE = "alerts.json"


# ==========================================
# LOAD CONFIG
# ==========================================

def load_config():

    if not os.path.exists(CONFIG_FILE):
        return {}

    try:
        with open(
            CONFIG_FILE,
            "r",
            encoding="utf-8"
        ) as file:
            return json.load(file)

    except (json.JSONDecodeError, OSError):

        print("[!] Could not read saved configuration.")
        return {}


# ==========================================
# SAVE CONFIG
# ==========================================

def save_config(config):

    try:

        with open(
            CONFIG_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                config,
                file,
                indent=4
            )

        # Linux: owner read/write only
        os.chmod(
            CONFIG_FILE,
            0o600
        )

        print(
            "\n[+] API keys saved successfully."
        )

    except OSError as e:

        print(
            "[!] Could not save configuration:",
            e
        )


# ==========================================
# API KEY MANAGEMENT
# ==========================================

def get_api_keys():

    config = load_config()

    vt_key = config.get(
        "virustotal_api_key"
    )

    abuse_key = config.get(
        "abuseipdb_api_key"
    )

    changed = False


    # --------------------------------------
    # VirusTotal
    # --------------------------------------

    if not vt_key:

        print(
            "\n[+] First-time API setup"
        )

        print(
            "-" * 50
        )

        vt_key = getpass.getpass(
            "Enter VirusTotal API Key: "
        ).strip()

        if not vt_key:

            print(
                "[!] VirusTotal API key cannot be empty."
            )

            raise SystemExit(1)

        config[
            "virustotal_api_key"
        ] = vt_key

        changed = True


    # --------------------------------------
    # AbuseIPDB
    # --------------------------------------

    if not abuse_key:

        abuse_key = getpass.getpass(
            "Enter AbuseIPDB API Key: "
        ).strip()

        if not abuse_key:

            print(
                "[!] AbuseIPDB API key cannot be empty."
            )

            raise SystemExit(1)

        config[
            "abuseipdb_api_key"
        ] = abuse_key

        changed = True


    if changed:

        save_config(config)


    return vt_key, abuse_key


# ==========================================
# IOC TYPE DETECTION
# ==========================================

def detect_ioc_type(ioc):

    # IPv4
    ip_pattern = (
        r"^(25[0-5]|2[0-4][0-9]|"
        r"[01]?[0-9][0-9]?)\."
        r"(25[0-5]|2[0-4][0-9]|"
        r"[01]?[0-9][0-9]?)\."
        r"(25[0-5]|2[0-4][0-9]|"
        r"[01]?[0-9][0-9]?)\."
        r"(25[0-5]|2[0-4][0-9]|"
        r"[01]?[0-9][0-9]?)$"
    )

    # SHA256
    sha256_pattern = (
        r"^[a-fA-F0-9]{64}$"
    )


    if re.match(
        ip_pattern,
        ioc
    ):

        return "IP"


    elif re.match(
        sha256_pattern,
        ioc
    ):

        return "SHA256"


    else:

        return "DOMAIN"


# ==========================================
# VIRUSTOTAL
# ==========================================

def check_virustotal(
    ioc,
    ioc_type,
    api_key
):

    result = {

        "malicious": 0,

        "suspicious": 0,

        "safe": 0,

        "no_verdict": 0,

        "total_platforms": 0,

        "malicious_platforms": [],

        "suspicious_platforms": [],

        "safe_platforms": [],

        "no_verdict_platforms": []
    }


    headers = {
        "x-apikey": api_key
    }


    # --------------------------------------
    # Endpoint
    # --------------------------------------

    if ioc_type == "IP":

        url = (
            "https://www.virustotal.com/api/v3/"
            f"ip_addresses/{ioc}"
        )

    elif ioc_type == "DOMAIN":

        url = (
            "https://www.virustotal.com/api/v3/"
            f"domains/{ioc}"
        )

    else:

        url = (
            "https://www.virustotal.com/api/v3/"
            f"files/{ioc}"
        )


    try:

        response = requests.get(
            url,
            headers=headers,
            timeout=15
        )


        print(
            "\n[+] VirusTotal HTTP Status:",
            response.status_code
        )


        # ----------------------------------
        # Error Handling
        # ----------------------------------

        if response.status_code != 200:

            if response.status_code == 401:

                print(
                    "[!] Invalid VirusTotal API key."
                )

            elif response.status_code == 404:

                print(
                    "[!] IOC not found in VirusTotal."
                )

            elif response.status_code == 429:

                print(
                    "[!] VirusTotal rate limit reached."
                )

            else:

                print(
                    "[!] VirusTotal error:",
                    response.status_code
                )

            return result


        # ----------------------------------
        # JSON Response
        # ----------------------------------

        vt_data = response.json()


        attributes = (
            vt_data
            .get("data", {})
            .get("attributes", {})
        )


        # ----------------------------------
        # Statistics
        # ----------------------------------

        stats = attributes.get(
            "last_analysis_stats",
            {}
        )


        result["malicious"] = stats.get(
            "malicious",
            0
        )


        result["suspicious"] = stats.get(
            "suspicious",
            0
        )


        result["safe"] = stats.get(
            "harmless",
            0
        )


        result["no_verdict"] = stats.get(
            "undetected",
            0
        )


        # ----------------------------------
        # Individual Platforms
        # ----------------------------------

        analysis_results = attributes.get(
            "last_analysis_results",
            {}
        )


        for (
            engine_name,
            engine_result
        ) in analysis_results.items():

            category = engine_result.get(
                "category"
            )


            if category == "malicious":

                result[
                    "malicious_platforms"
                ].append(
                    engine_name
                )


            elif category == "suspicious":

                result[
                    "suspicious_platforms"
                ].append(
                    engine_name
                )


            elif category == "harmless":

                result[
                    "safe_platforms"
                ].append(
                    engine_name
                )


            elif category == "undetected":

                result[
                    "no_verdict_platforms"
                ].append(
                    engine_name
                )


        result["total_platforms"] = (
            len(analysis_results)
        )


    except requests.exceptions.RequestException as e:

        print(
            "[!] VirusTotal network error:",
            e
        )


    return result


# ==========================================
# ABUSEIPDB
# ==========================================

def check_abuseipdb(
    ip,
    api_key
):

    result = {

        "abuse_score": 0,

        "country": None,

        "isp": None,

        "total_reports": 0,

        "usage_type": None,

        "domain": None
    }


    url = (
        "https://api.abuseipdb.com/api/v2/check"
    )


    headers = {

        "Key": api_key,

        "Accept": "application/json"
    }


    params = {

        "ipAddress": ip,

        "maxAgeInDays": 90
    }


    try:

        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=15
        )


        print(
            "\n[+] AbuseIPDB HTTP Status:",
            response.status_code
        )


        if response.status_code == 200:

            data = response.json().get(
                "data",
                {}
            )


            result["abuse_score"] = data.get(
                "abuseConfidenceScore",
                0
            )


            result["country"] = data.get(
                "countryCode"
            )


            result["isp"] = data.get(
                "isp"
            )


            result["total_reports"] = data.get(
                "totalReports",
                0
            )


            result["usage_type"] = data.get(
                "usageType"
            )


            result["domain"] = data.get(
                "domain"
            )


        elif response.status_code == 401:

            print(
                "[!] Invalid AbuseIPDB API key."
            )


        elif response.status_code == 429:

            print(
                "[!] AbuseIPDB rate limit reached."
            )


        else:

            print(
                "[!] AbuseIPDB error:",
                response.status_code
            )


    except requests.exceptions.RequestException as e:

        print(
            "[!] AbuseIPDB network error:",
            e
        )


    return result


# ==========================================
# SEVERITY
# ==========================================

def calculate_severity(
    vt,
    abuse
):

    if (
        vt["malicious"] > 0
        or abuse["abuse_score"] >= 50
    ):

        return "HIGH"


    elif (
        vt["suspicious"] > 0
        or abuse["abuse_score"] > 0
    ):

        return "MEDIUM"


    else:

        return "LOW"


# ==========================================
# DISPLAY VIRUSTOTAL
# ==========================================

def display_virustotal(vt):

    print("\n")

    print(
        "=" * 120
    )

    print(
        "                 VIRUSTOTAL PLATFORM VERDICTS"
    )

    print(
        "=" * 120
    )


    # --------------------------------------
    # Four Horizontal Sections
    # --------------------------------------

    print(
        f"{'🚨 DECLARED MALICIOUS':<30}"
        f"{'⚠️ DECLARED SUSPICIOUS':<30}"
        f"{'✅ DECLARED SAFE':<30}"
        f"{'❔ NO VERDICT':<30}"
    )


    print(
        f"{vt['malicious']:<30}"
        f"{vt['suspicious']:<30}"
        f"{vt['safe']:<30}"
        f"{vt['no_verdict']:<30}"
    )


    print(
        "-" * 120
    )


    malicious = vt[
        "malicious_platforms"
    ]

    suspicious = vt[
        "suspicious_platforms"
    ]

    safe = vt[
        "safe_platforms"
    ]

    no_verdict = vt[
        "no_verdict_platforms"
    ]


    max_rows = max(
        len(malicious),
        len(suspicious),
        len(safe),
        len(no_verdict)
    )


    # --------------------------------------
    # Platform Names
    # --------------------------------------

    for i in range(max_rows):

        malicious_name = ""

        suspicious_name = ""

        safe_name = ""

        no_verdict_name = ""


        if i < len(malicious):

            malicious_name = (
                f"{i + 1}. {malicious[i]}"
            )


        if i < len(suspicious):

            suspicious_name = (
                f"{i + 1}. {suspicious[i]}"
            )


        if i < len(safe):

            safe_name = (
                f"{i + 1}. {safe[i]}"
            )


        if i < len(no_verdict):

            no_verdict_name = (
                f"{i + 1}. {no_verdict[i]}"
            )


        print(
            f"{malicious_name:<30}"
            f"{suspicious_name:<30}"
            f"{safe_name:<30}"
            f"{no_verdict_name:<30}"
        )


    print(
        "=" * 120
    )


    print(
        "Total Platforms Checked:",
        vt["total_platforms"]
    )


# ==========================================
# DISPLAY ABUSEIPDB
# ==========================================

def display_abuseipdb(abuse):

    score = abuse["abuse_score"]


    # --------------------------------------
    # Determine Reputation
    # --------------------------------------

    if score >= 50:

        verdict = "HIGH RISK"

    elif score > 0:

        verdict = "SUSPICIOUS"

    else:

        verdict = "LOW RISK"


    print("\n")

    print(
        "=" * 75
    )

    print(
        "                    ABUSEIPDB REPUTATION"
    )

    print(
        "=" * 75
    )


    print(
        f"{'🚨 HIGH RISK':<25}"
        f"{'⚠️ SUSPICIOUS':<25}"
        f"{'✅ LOW RISK':<25}"
    )


    high_risk = "YES" if score >= 50 else "NO"

    suspicious = (
        "YES"
        if 0 < score < 50
        else "NO"
    )

    low_risk = (
        "YES"
        if score == 0
        else "NO"
    )


    print(
        f"{high_risk:<25}"
        f"{suspicious:<25}"
        f"{low_risk:<25}"
    )


    print(
        "-" * 75
    )


    print(
        "Reputation Assessment :",
        verdict
    )


    print(
        "Abuse Confidence Score:",
        score
    )


    print(
        "Country               :",
        abuse["country"]
    )


    print(
        "ISP                   :",
        abuse["isp"]
    )


    print(
        "Domain                :",
        abuse["domain"]
    )


    print(
        "Usage Type            :",
        abuse["usage_type"]
    )


    print(
        "Total Reports         :",
        abuse["total_reports"]
    )


# ==========================================
# SAVE ALERT
# ==========================================

def save_alert(alert):

    alerts = []


    if os.path.exists(ALERT_FILE):

        try:

            with open(
                ALERT_FILE,
                "r",
                encoding="utf-8"
            ) as file:

                alerts = json.load(file)


            if not isinstance(
                alerts,
                list
            ):

                alerts = []


        except (
            json.JSONDecodeError,
            OSError
        ):

            alerts = []


    alerts.append(
        alert
    )


    with open(
        ALERT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            alerts,
            file,
            indent=4
        )


# ==========================================
# MAIN
# ==========================================

def main():

    print(
        "=" * 60
    )

    print(
        "                    IOC CHECKER"
    )

    print(
        "=" * 60
    )

    print(
        "\n[+] Type 'exit' anytime to close."
    )


    # --------------------------------------
    # API Keys
    # --------------------------------------

    vt_key, abuse_key = get_api_keys()


    print(
        "\n[+] API configuration loaded."
    )


    # ======================================
    # IOC LOOP
    # ======================================

    while True:

        print(
            "\n"
            + "-" * 60
        )


        ioc = input(
            "Enter IP / Domain / SHA256: "
        ).strip()


        # ----------------------------------
        # Exit
        # ----------------------------------

        if ioc.lower() == "exit":

            print(
                "\n[+] IOC Checker closed."
            )

            break


        # ----------------------------------
        # Empty Input
        # ----------------------------------

        if not ioc:

            print(
                "[!] IOC cannot be empty."
            )

            continue


        # ----------------------------------
        # Detect IOC Type
        # ----------------------------------

        ioc_type = detect_ioc_type(
            ioc
        )


        print(
            "\nIOC  :",
            ioc
        )

        print(
            "Type :",
            ioc_type
        )


        # ----------------------------------
        # VirusTotal
        # ----------------------------------

        print(
            "\n[+] Checking VirusTotal..."
        )


        vt_result = check_virustotal(
            ioc,
            ioc_type,
            vt_key
        )


        display_virustotal(
            vt_result
        )


        # ----------------------------------
        # AbuseIPDB
        # ----------------------------------

        if ioc_type == "IP":

            print(
                "\n[+] Checking AbuseIPDB..."
            )


            abuse_result = check_abuseipdb(
                ioc,
                abuse_key
            )


            display_abuseipdb(
                abuse_result
            )


        else:

            print(
                "\n[+] AbuseIPDB skipped."
            )

            print(
                "    AbuseIPDB check requires an IP address."
            )


            abuse_result = {

                "abuse_score": 0,

                "country": None,

                "isp": None,

                "total_reports": 0,

                "usage_type": None,

                "domain": None
            }


        # ----------------------------------
        # Severity
        # ----------------------------------

        severity = calculate_severity(
            vt_result,
            abuse_result
        )


        # ----------------------------------
        # Final SOC Alert
        # ----------------------------------

        alert = {

            "timestamp":
                datetime.now().isoformat(),

            "ioc":
                ioc,

            "type":
                ioc_type,

            "severity":
                severity,

            "virustotal":
                vt_result,

            "abuseipdb":
                abuse_result
        }


        print(
            "\n"
            + "=" * 60
        )

        print(
            "                  FINAL SOC ALERT"
        )

        print(
            "=" * 60
        )


        print(
            "IOC      :",
            ioc
        )


        print(
            "Type     :",
            ioc_type
        )


        print(
            "Severity :",
            severity
        )


        # ----------------------------------
        # Save
        # ----------------------------------

        save_alert(
            alert
        )


        print(
            "\n[+] Alert saved to:",
            ALERT_FILE
        )


        print(
            "[+] Ready for next IOC..."
        )


# ==========================================
# START
# ==========================================

if __name__ == "__main__":

    main()