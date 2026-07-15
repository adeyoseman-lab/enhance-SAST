import json


def load_sarif(file):

    with open(file, encoding="utf8") as f:
        return json.load(f)


def save_sarif(data, file):

    with open(file, "w", encoding="utf8") as f:
        json.dump(data, f, indent=2)


def driver(sarif):

    return sarif["runs"][0]["tool"]["driver"]


def rules(sarif):

    return driver(sarif).get("rules", [])


def results(sarif):

    return sarif["runs"][0]["results"]