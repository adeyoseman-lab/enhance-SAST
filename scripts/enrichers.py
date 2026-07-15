from severity import cvss_to_level


def enrich_rule(rule, metadata):

    score = metadata["cvss"]

    severity, level = cvss_to_level(score)

    rule["name"] = metadata["title"]

    rule["shortDescription"] = {
        "text": metadata["title"]
    }

    rule["fullDescription"] = {
        "text": metadata["description"]
    }

    rule["help"] = {
        "text": f"""
Severity
--------
{severity}

CVSS
----
{score}

OWASP
------
{metadata["owasp"]}

CWE
---
{metadata["cwe"]}

Impact
------
{metadata["impact"]}

How To Fix
----------
{metadata["fix"]}

References
----------
{chr(10).join(metadata["references"])}
"""
    }

    rule["helpUri"] = metadata["references"][0]

    props = rule.setdefault("properties", {})

    props["security-severity"] = str(score)

    props["problem.severity"] = level

    props["precision"] = "high"

    props["tags"] = [
        "security",
        metadata["owasp"],
        metadata["cwe"]
    ]

    return severity, level


def enrich_result(result, score, level):

    result["level"] = level

    props = result.setdefault("properties", {})

    props["security-severity"] = str(score)