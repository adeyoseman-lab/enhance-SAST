from sarif_utils import load_sarif, save_sarif
from rule_mapper import map_rule
from sarif_builder import update_rule, update_result

sarif = load_sarif("snyk.sarif")

driver = sarif["runs"][0]["tool"]["driver"]

rule_map = {}

for rule in driver.get("rules", []):

    rule_map[rule["id"]] = rule

for result in sarif["runs"][0]["results"]:

    meta = map_rule(result["ruleId"])

    if meta is None:
        continue

    update_rule(rule_map[result["ruleId"]], meta)

    update_result(result, meta)

save_sarif(
    sarif,
    "snyk-enhanced.sarif"
)

print("Done")
