#!/usr/bin/env python3
# merge_findings.py

import argparse
import csv
import os
import re
import xml.etree.ElementTree as ET


# columns of the output CSV
COLUMNS = ["tool", "source_file", "host", "phase", "port", "protocol", "service",
           "category", "finding_id", "title", "severity", "severity_label",
           "cvss_version", "qod", "cves", "topic"]

# ports from this number up are random RPC ports, they change after a restart
DYNAMIC_PORT = 32768

# keyword rules for sorting findings into topics (first match wins)
TOPIC_RULES = [
    ["backdoor / remote code execution", r"backdoor|bindshell|root shell|ingreslock|command execution|\brce\b|remote shell|distcc|druby|java rmi|rmi-vuln|unrealircd"],
    ["passwords and login", r"password|credential|brute|rlogin|rexec|\brsh\b|login"],
    ["SSH configuration", r"ssh"],
    ["TLS / encryption", r"ssl|tls|cipher|certificate|diffie|poodle|ccs injection|cleartext|unencrypted|freak|logjam"],
    ["firewall", r"firewall|iptables|ufw"],
    ["kernel settings", r"kernel|sysctl"],
    ["information disclosure", r"timestamp|phpinfo|disclosure|vrfy|browsable|trace"],
    ["packages and updates", r"package|end of life|\beol\b|update"],
    ["logging and auditing", r"syslog|audit|accounting"],
    ["web application", r"http|php|twiki|apache|jquery|tomcat|xss|csrf|wiki"],
    ["denial of service", r"slowloris|denial"],
]

# Lynis test IDs start with a group name, e.g. SSH-7408
LYNIS_GROUPS = {
    "SSH": "SSH configuration",
    "AUTH": "passwords and login",
    "FIRE": "firewall",
    "KRNL": "kernel settings",
    "NETW": "network protocols",
    "USB": "USB and devices",
    "BANN": "login banners",
    "ACCT": "logging and auditing",
    "LOGG": "logging and auditing",
    "PKGS": "packages and updates",
    "FILE": "files and permissions",
    "BOOT": "boot and services",
    "HRDN": "hardening tools",
    "FINT": "hardening tools",
    "MALW": "hardening tools",
    "NAME": "DNS",
    "TOOL": "other",
}


def get_topic(text):
    # Lynis findings: use the test ID group
    match = re.match(r"^([A-Z]+)-\d{4}", text)
    if match and match.group(1) in LYNIS_GROUPS:
        return LYNIS_GROUPS[match.group(1)]

    # other findings: use the keyword rules
    text = text.lower()
    for rule in TOPIC_RULES:
        name = rule[0]
        pattern = rule[1]
        if re.search(pattern, text):
            return name
    return "other"


def get_phase(path):
    # scans after hardening have "after" in the file name
    if "after" in os.path.basename(path).lower():
        return "after hardening"
    return "baseline"


def port_key(port, protocol):
    # random RPC ports are grouped together
    if port.isdigit() and int(port) >= DYNAMIC_PORT:
        return "dynamic/" + protocol
    return port + "/" + protocol


def new_row(tool, source_file, host, port, protocol):
    # empty row with all columns
    row = {}
    for column in COLUMNS:
        row[column] = ""
    row["tool"] = tool
    row["source_file"] = source_file
    row["host"] = host
    row["phase"] = get_phase(source_file)
    row["port"] = port
    row["protocol"] = protocol
    return row


# ---------- Nmap ----------

def script_is_vulnerable(script):
    # check the "state" field of the script
    for elem in script.iter("elem"):
        if elem.get("key") == "state":
            state = elem.text or ""
            if "VULNERABLE" in state and "NOT VULNERABLE" not in state:
                return True

    output = script.get("output", "")
    if re.search(r"(?<!NOT )VULNERABLE", output):
        return True

    # the UnrealIRCd script has no state field
    if "trojaned version" in output.lower():
        return True
    return False


def script_title(script):
    output = script.get("output", "")
    lines = []
    for line in output.splitlines():
        line = line.strip()
        if line != "":
            lines.append(line)

    # the line after "VULNERABLE:" is the name of the problem
    for i in range(len(lines) - 1):
        if lines[i].startswith("VULNERABLE"):
            return lines[i + 1]

    if len(lines) > 0:
        return lines[0][:120]
    return script.get("id")


def script_cves(script):
    cves = []
    texts = [script.get("output", "")]
    for elem in script.iter("elem"):
        texts.append(elem.text or "")

    for text in texts:
        for cve in re.findall(r"CVE-\d{4}-\d{4,}", text):
            if cve not in cves:
                cves.append(cve)
    cves.sort()
    return cves


def parse_nmap(path):
    rows = []
    root = ET.parse(path).getroot()

    for host in root.iter("host"):
        address = host.find("address").get("addr")

        for port in host.iter("port"):
            state = port.find("state").get("state")
            if "open" not in state:
                continue

            number = port.get("portid")
            protocol = port.get("protocol")
            service_name = ""
            banner = ""
            service = port.find("service")
            if service is not None:
                service_name = service.get("name", "")
                banner = service.get("product", "") + " " + service.get("version", "") + " " + service.get("extrainfo", "")
                banner = banner.strip()

            # one row for the open port
            row = new_row("nmap", path, address, number, protocol)
            row["service"] = service_name
            row["category"] = "open-port"
            row["finding_id"] = state
            if banner != "":
                row["title"] = banner
            else:
                row["title"] = service_name
            row["topic"] = "open port"
            rows.append(row)

            # one row for every script that found a vulnerability
            for script in port.findall("script"):
                if not script_is_vulnerable(script):
                    continue

                title = script_title(script)
                row = new_row("nmap", path, address, number, protocol)
                row["service"] = service_name
                row["category"] = "vulnerability"
                row["finding_id"] = script.get("id")
                row["title"] = title
                row["cves"] = " ".join(script_cves(script))
                row["topic"] = get_topic(script.get("id") + " " + title)
                rows.append(row)

    return rows


# ---------- Greenbone ----------

def parse_greenbone(path, min_qod):
    rows = []
    root = ET.parse(path).getroot()

    report = root.find("report")
    if report is None:
        report = root
    results = report.find("results")
    if results is None:
        return rows

    seen_ids = []
    for result in results.findall("result"):
        # the export sometimes repeats a result
        if result.get("id") in seen_ids:
            continue
        seen_ids.append(result.get("id"))

        # same filter as the default Greenbone report
        qod = int(result.findtext("qod/value", "0"))
        if qod < min_qod:
            continue

        # port looks like "21/tcp" or "general/tcp"
        port_text = result.findtext("port", "")
        parts = port_text.split("/")
        number = parts[0]
        protocol = ""
        if len(parts) > 1:
            protocol = parts[1]

        host = (result.findtext("host") or "").strip()
        title = result.findtext("name", "").strip()
        threat = result.findtext("threat", "")

        row = new_row("greenbone", path, host, number, protocol)
        if threat == "Log":
            row["category"] = "log"
        else:
            row["category"] = "vulnerability"
        row["title"] = title
        row["severity"] = result.findtext("severity", "")
        row["severity_label"] = threat
        row["qod"] = str(qod)

        nvt = result.find("nvt")
        if nvt is not None:
            row["finding_id"] = nvt.get("oid")
            # CVSS version, e.g. "cvss_base_v2" -> "v2"
            severities = nvt.find("severities")
            if severities is not None:
                first = severities.find("severity")
                if first is not None:
                    row["cvss_version"] = first.get("type", "").replace("cvss_base_", "")

        cves = []
        for ref in result.iter("ref"):
            if ref.get("type") == "cve" and ref.get("id") not in cves:
                cves.append(ref.get("id"))
        cves.sort()
        row["cves"] = " ".join(cves)

        row["topic"] = get_topic(title + " " + port_text)
        rows.append(row)

    return rows


# ---------- Lynis ----------

def parse_lynis(path):
    rows = []
    host = ""
    file = open(path, encoding="utf-8", errors="replace")
    lines = file.read().splitlines()
    file.close()

    # IP address of the server (not 127.0.0.1)
    for line in lines:
        if line.startswith("network_ipv4_address[]="):
            address = line.split("=", 1)[1]
            if not address.startswith("127.") and host == "":
                host = address

    for line in lines:
        # lines look like: suggestion[]=SSH-7408|text|details|solution|
        if line.startswith("warning[]="):
            kind = "warning"
        elif line.startswith("suggestion[]="):
            kind = "suggestion"
        else:
            continue

        parts = line.split("=", 1)[1].split("|")
        test_id = parts[0]
        text = ""
        if len(parts) > 1:
            text = parts[1]
        title = text
        if len(parts) > 2 and parts[2] != "-":
            title = text + " (" + parts[2] + ")"

        row = new_row("lynis", path, host, "-", "local")
        row["category"] = kind
        row["finding_id"] = test_id
        row["title"] = title
        row["severity_label"] = kind
        row["topic"] = get_topic(test_id + " " + text)
        rows.append(row)

    return rows


# ---------- summary ----------

def add_count(counts, key):
    if key in counts:
        counts[key] = counts[key] + 1
    else:
        counts[key] = 1


def make_summary(title, rows, out):
    out.append("")
    out.append("##### " + title + " #####")

    # findings per tool and category
    out.append("")
    out.append("=== Findings per tool and category ===")
    counts = {}
    for row in rows:
        add_count(counts, row["tool"] + "  " + row["category"])
    for key in sorted(counts):
        out.append("  " + key + ": " + str(counts[key]))

    # Greenbone severity and CVSS versions
    severity = {}
    versions = {}
    for row in rows:
        if row["tool"] == "greenbone" and row["category"] == "vulnerability":
            add_count(severity, row["severity_label"])
            add_count(versions, row["cvss_version"])
    if len(severity) > 0:
        out.append("")
        out.append("=== Greenbone severity (without Log) ===")
        for label in ["Critical", "High", "Medium", "Low"]:
            if label in severity:
                out.append("  " + label + ": " + str(severity[label]))
        out.append("  CVSS versions: " + str(versions))

    # which tools found something on which port
    ports = {}
    cves = {}
    for row in rows:
        if row["category"] != "vulnerability" or not row["port"].isdigit():
            continue
        key = port_key(row["port"], row["protocol"])
        if key not in ports:
            ports[key] = []
        if row["tool"] not in ports[key]:
            ports[key].append(row["tool"])
        for cve in row["cves"].split():
            if cve not in cves:
                cves[cve] = []
            if row["tool"] not in cves[cve]:
                cves[cve].append(row["tool"])

    if len(ports) > 0:
        both = []
        only_nmap = []
        only_greenbone = []
        for key in sorted(ports):
            if len(ports[key]) == 2:
                both.append(key)
            elif ports[key][0] == "nmap":
                only_nmap.append(key)
            else:
                only_greenbone.append(key)
        shared_cves = []
        for cve in sorted(cves):
            if len(cves[cve]) > 1:
                shared_cves.append(cve)

        out.append("")
        out.append("=== Ports with a vulnerability finding ===")
        out.append("  both tools (" + str(len(both)) + "): " + ", ".join(both))
        out.append("  only Nmap (" + str(len(only_nmap)) + "): " + ", ".join(only_nmap))
        out.append("  only Greenbone (" + str(len(only_greenbone)) + "): " + ", ".join(only_greenbone))
        out.append("  CVEs reported by both (" + str(len(shared_cves)) + "): " + " ".join(shared_cves))

    # findings by topic
    topics = {}
    for row in rows:
        if row["category"] in ["vulnerability", "warning", "suggestion"]:
            if row["topic"] not in topics:
                topics[row["topic"]] = {"nmap": 0, "greenbone": 0, "lynis": 0}
            topics[row["topic"]][row["tool"]] += 1
    if len(topics) > 0:
        out.append("")
        out.append("=== Findings by topic (nmap / greenbone / lynis) ===")
        for topic in sorted(topics):
            t = topics[topic]
            out.append("  " + topic + ": " + str(t["nmap"]) + " / " + str(t["greenbone"]) + " / " + str(t["lynis"]))


def write_csv(path, rows):
    file = open(path, "w", newline="", encoding="utf-8")
    writer = csv.DictWriter(file, fieldnames=COLUMNS)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    file.close()


def detect_tool(path):
    # Lynis report is a text file that starts with "# Lynis Report"
    if path.endswith(".dat"):
        file = open(path, encoding="utf-8", errors="replace")
        first_line = file.readline()
        file.close()
        if first_line.startswith("# Lynis Report"):
            return "lynis"
        return None

    # Nmap and Greenbone are both XML, the root element tells them apart
    if path.endswith(".xml"):
        try:
            root = ET.parse(path).getroot()
        except ET.ParseError:
            return None
        if root.tag == "nmaprun":
            return "nmap"
        if root.tag == "report" or root.tag == "get_reports_response":
            return "greenbone"
    return None


def main():
    parser = argparse.ArgumentParser(description="Merge Nmap, Greenbone and Lynis results into one CSV.")
    parser.add_argument("input", nargs="?", default="input", help="folder with the scan files (default: input)")
    parser.add_argument("output", nargs="?", default="output", help="folder for the results (default: output)")
    parser.add_argument("--min-qod", type=int, default=70, help="minimum Greenbone QoD (default 70)")
    args = parser.parse_args()

    if not os.path.isdir(args.input):
        parser.error("input folder not found: " + args.input)
    if not os.path.isdir(args.output):
        os.makedirs(args.output)

    # read every file in the input folder
    rows = []
    for name in sorted(os.listdir(args.input)):
        path = os.path.join(args.input, name)
        tool = detect_tool(path)
        if tool == "nmap":
            rows = rows + parse_nmap(path)
        elif tool == "greenbone":
            rows = rows + parse_greenbone(path, args.min_qod)
        elif tool == "lynis":
            rows = rows + parse_lynis(path)
        else:
            print("Skipped (not a scan result): " + name)
            continue
        print("Read " + tool + ": " + name)

    if len(rows) == 0:
        print("No findings found in " + args.input)
        return

    csv_path = os.path.join(args.output, "findings.csv")
    write_csv(csv_path, rows)

    # one summary for every host and phase (baseline / after hardening)
    groups = {}
    for row in rows:
        key = row["host"] + " " + row["phase"]
        if key not in groups:
            groups[key] = []
        groups[key].append(row)

    lines = []
    for key in groups:
        make_summary(key, groups[key], lines)

    summary_path = os.path.join(args.output, "summary.txt")
    file = open(summary_path, "w", encoding="utf-8")
    file.write("\n".join(lines) + "\n")
    file.close()

    print("\n".join(lines))
    print("")
    print("Wrote " + str(len(rows)) + " rows to " + csv_path)
    print("Wrote summary to " + summary_path)


main()
