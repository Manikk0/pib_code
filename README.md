# merge_findings.py

Merges the results of Nmap, Greenbone (OpenVAS) and Lynis into one CSV file
and writes a short summary for every scanned host, separately for the
baseline and for the scans after hardening.

Needs only Python 3, no extra packages.

## Usage

1. Put the scan files into the folder `input`.
2. Run:

```
python merge_findings.py
```

3. The results are in the folder `output`:
   * `findings.csv` – all findings in one table
   * `summary.txt` – summary for every host (also printed to the terminal)

Other folders can be given as arguments:

```
python merge_findings.py my_input my_output
```

## Input files

| Tool      | File   | How to get it |
|-----------|--------|---------------|
| Nmap      | `.xml` | `nmap ... -oX name.xml` or `-oA name` |
| Greenbone | `.xml` | report downloaded in the XML format |
| Lynis     | `.dat` | `/var/log/lynis-report.dat` after `lynis audit system` |

The tool is recognised from the content of the file, not from its name.
Other files in the folder (for example `.nmap` and `.gnmap`) are skipped.

## Rules for correct results

1. **Files from the scans after hardening must contain `after` in their
   name**, e.g. `nmap_ubu_tcp_after.xml`. All other files count as baseline.
2. **One Greenbone report per host and phase.** If the folder contains two
   reports of the same host (for example an unauthenticated and an
   authenticated one, or the same report exported with a different QoD
   filter), their results are counted twice.
3. **Lynis must report the same IP address that the scanners used.**
   The script takes the host from the first non-local IPv4 address in the
   Lynis report. If the server has another address there first (e.g. from a
   NAT adapter), its findings end up under a different host.

## Output columns

| Column | Meaning |
|--------|---------|
| tool | nmap, greenbone or lynis |
| source_file | input file the finding came from |
| host | IP address of the target |
| phase | baseline or after hardening |
| port, protocol, service | where the finding is (empty for Lynis) |
| category | open-port, vulnerability, log, warning or suggestion |
| finding_id | Nmap script name, Greenbone OID or Lynis test ID |
| title | short description |
| severity, severity_label | CVSS score and Greenbone threat level |
| cvss_version | CVSS version Greenbone used for the score |
| qod | Greenbone Quality of Detection |
| cves | CVE IDs separated by spaces |
| topic | rough topic used to compare the tools |

## Notes

* Ports from 32768 up are grouped as one "dynamic" port in the summary,
  because RPC services (e.g. Java RMI) get a new random port after a restart.
* Topics are assigned by simple keyword rules, so a few findings may end up
  in the wrong topic.
