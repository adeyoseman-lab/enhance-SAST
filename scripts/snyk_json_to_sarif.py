import json

with open("snyk.json") as f:
    data = json.load(f)

sarif = {
    "version": "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [{
        "tool": {
            "driver": {
                "name": "Snyk",
                "rules": []
            }
        },
        "results": []
    }]
}

run = sarif["runs"][0]

for issue in data.get("runs", []):

    rule = {
        "id": issue["ruleId"],
        "name": issue["ruleId"],
        "shortDescription": {
            "text": issue["message"]
        }
    }

    run["tool"]["driver"]["rules"].append(rule)

    result = {
        "ruleId": issue["ruleId"],
        "level": "warning",
        "message": {
            "text": issue["message"]
        },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": issue["path"]
                },
                "region": {
                    "startLine": issue["line"]
                }
            }
        }]
    }

    run["results"].append(result)

with open("snyk.sarif", "w") as f:
    json.dump(sarif, f, indent=2)
