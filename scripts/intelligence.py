from loaders import *

RULES = load_semgrep_rules()

ALIASES = load_aliases()

CWE = load_cwe()

OWASP = load_owasp()

CAPEC = load_capec()

CVSS = load_cvss()


def find_rule(rule):

    if rule in RULES:

        return RULES[rule]

    if rule in ALIASES:

        cwe = ALIASES[rule]

        for r in RULES.values():

            if r["cwe"] == cwe:

                return r

    return None