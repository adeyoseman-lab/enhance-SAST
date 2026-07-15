import json

INPUT="snyk-code.json"
OUTPUT="snyk.sarif"

with open(INPUT,"r",encoding="utf-8") as f:
    data=json.load(f)

sarif={
    "version":"2.1.0",
    "$schema":"https://json.schemastore.org/sarif-2.1.0.json",
    "runs":[{
        "tool":{"driver":{"name":"Snyk","rules":[]}},
        "results":[]
    }]
}

run=sarif["runs"][0]
rules={}

issues=data.get("issues",[])
if not issues and isinstance(data,dict):
    issues=data.get("runs",[])

for issue in issues:
    rid=issue.get("ruleId") or issue.get("id") or "SNYK-UNKNOWN"
    title=issue.get("title") or issue.get("message") or rid
    severity=(issue.get("severity") or "medium").lower()
    if rid not in rules:
        rules[rid]={
            "id":rid,
            "name":title,
            "shortDescription":{"text":title},
            "defaultConfiguration":{
                "level":"error" if severity in ("critical","high") else "warning"
            }
        }
    run["results"].append({
        "ruleId":rid,
        "level":"error" if severity in ("critical","high") else "warning",
        "message":{"text":title},
        "locations":[{
            "physicalLocation":{
                "artifactLocation":{"uri":issue.get("filePath","unknown")},
                "region":{"startLine":issue.get("line",1)}
            }
        }]
    })

run["tool"]["driver"]["rules"]=list(rules.values())

with open(OUTPUT,"w",encoding="utf-8") as f:
    json.dump(sarif,f,indent=2)

print(f"Wrote {OUTPUT}")
