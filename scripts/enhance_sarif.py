from sarif_utils import load_sarif, save_sarif
from loaders import (
    load_cwe,
    load_owasp,
    load_capec,
    load_cvss,
    load_semgrep_rules,
)

INPUT = "semgrep.sarif"
OUTPUT = "semgrep-enhanced.sarif"

sarif = load_sarif(INPUT)

cwe = load_cwe()
owasp = load_owasp()
capec = load_capec()
cvss = load_cvss()
rules = load_semgrep_rules()

print(f"CWE Loaded      : {len(cwe)}")
print(f"OWASP Loaded    : {len(owasp)}")
print(f"CAPEC Loaded    : {len(capec)}")
print(f"CVSS Loaded     : {len(cvss)}")
print(f"Semgrep Rules   : {len(rules)}")

#
# Part 2 akan mulai enrich SARIF
#

save_sarif(sarif, OUTPUT)

print("Enhanced SARIF generated.")