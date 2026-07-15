def build_help(meta):

    refs = "\n".join(
        f"- {r}"
        for r in meta["references"]
    )

    return f"""
# {meta['title']}

---

## Severity

**{meta['severity']}**

CVSS Score : **{meta['cvss']}**

---

## Description

{meta['description']}

---

## Impact

{meta['impact']}

---

## OWASP Top 10

{meta['owasp']}

---

## CWE

{meta['cwe']}

---

## CAPEC

{meta.get('capec','N/A')}

---

## Remediation

{meta['fix']}

---

## References

{refs}

"""