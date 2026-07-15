from loaders import (
    load_semgrep_rules,
    load_cwe,
    load_owasp,
    load_capec
)

RULES = load_semgrep_rules()

CWE = load_cwe()

OWASP = load_owasp()

CAPEC = load_capec()


def map_rule(rule):

    if rule not in RULES:

        return None

    data = RULES[rule]

    data["cwe_data"] = CWE.get(
        data["cwe"],
        {}
    )

    data["owasp_data"] = OWASP.get(
        data["owasp"],
        {}
    )

    data["capec_data"] = CAPEC.get(
        data.get("capec",""),
        {}
    )

    return data