import os
import sys

from sarif_utils import load_sarif, save_sarif
from sarif_builder import update_rule, update_result
from rule_mapper import map_rule

INPUT = "snyk.sarif"
OUTPUT = "snyk-enhanced.sarif"

if not os.path.exists(INPUT):
    print(f"{INPUT} not found")
    sys.exit(0)

sarif = load_sarif(INPUT)

run = sarif["runs"][0]

driver = run["tool"]["driver"]

rule_index = {}

for rule in driver.get("rules", []):
    rule_index[rule["id"]] = rule

for result in run.get("results", []):

    rule_id = result["ruleId"]

    meta = map_rule(rule_id)

    if meta is None:
        continue

    if rule_id in rule_index:
        update_rule(rule_index[rule_id], meta)

    update_result(result, meta)

save_sarif(sarif, OUTPUT)

print("Enhanced Successfully")
