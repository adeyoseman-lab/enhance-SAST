from sarif_utils import load_sarif, save_sarif

from taxonomy_builder import build_taxonomies

from sarif_builder import (
    update_rule,
    update_result,
    add_fixes,
    add_relationship
)

from rule_mapper import map_rule

INPUT="semgrep.sarif"

OUTPUT="semgrep-enhanced.sarif"

sarif = load_sarif(INPUT)

run = sarif["runs"][0]

driver = run["tool"]["driver"]

driver["taxonomies"] = build_taxonomies()

rule_index = {}

for rule in driver.get(
    "rules",
    []
):

    rule_index[rule["id"]] = rule

for result in run["results"]:

    meta = map_rule(
        result["ruleId"]
    )

    if meta is None:

        continue

    update_rule(
        rule_index[result["ruleId"]],
        meta
    )

    update_result(
        result,
        meta
    )

    add_fixes(
        result,
        meta
    )

    add_relationship(
        rule_index[result["ruleId"]],
        meta
    )

save_sarif(
    sarif,
    OUTPUT
)

print("Enhanced Successfully")