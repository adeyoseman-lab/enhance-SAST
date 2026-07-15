import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "security-db"


def load_json(name):

    with open(DB / name, encoding="utf8") as f:
        return json.load(f)


def load_cwe():
    return load_json("cwe.json")


def load_owasp():
    return load_json("owasp.json")


def load_capec():
    return load_json("capec.json")


def load_cvss():
    return load_json("cvss.json")


def load_semgrep_rules():
    return load_json("semgrep-rules.json")