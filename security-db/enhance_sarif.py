from sarif_utils import load_sarif, save_sarif
from loaders import load_semgrep_rules
from enrichers import enrich_rule, enrich_result

INPUT = "semgrep.sarif"
OUTPUT = "semgrep-enhanced.sarif"

sarif = load_sarif(INPUT)

mapping = load_semgrep_rules()

driver = sarif["runs"][0]["tool"]["driver"]

rules = {}

for r in driver.get("rules", []):
    rules[r["id"]] = r

for result in sarif["runs"][0]["results"]:

    rid = result["ruleId"]

    if rid not in mapping:
        continue

    meta = mapping[rid]

    severity, level = enrich_rule(
        rules[rid],
        meta
    )

    enrich_result(
        result,
        meta["cvss"],
        level
    )

save_sarif(
    sarif,
    OUTPUT
)

print("SARIF Enhanced Successfully.")