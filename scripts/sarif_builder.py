from markdown_builder import build_help


def update_rule(rule, meta):

    props = rule.setdefault(
        "properties",
        {}
    )

    props["security-severity"] = str(meta["cvss"])

    props["problem.severity"] = meta["github_level"]

    props["precision"] = "very-high"

    props["tags"] = [

        "security",

        meta["owasp"],

        meta["cwe"],

        meta.get("capec","")
    ]

    rule["name"] = meta["title"]

    rule["shortDescription"] = {

        "text":meta["title"]

    }

    rule["fullDescription"] = {

        "text":meta["description"]

    }

    rule["help"] = {

        "text":build_help(meta),

        "markdown":build_help(meta)

    }

    rule["helpUri"] = meta["references"][0]

    rule["defaultConfiguration"] = {

        "level":meta["github_level"]

    }


def update_result(result, meta):

    result["level"] = meta["github_level"]

    props = result.setdefault(
        "properties",
        {}
    )

    props["security-severity"] = str(meta["cvss"])

    props["tags"]=[

        meta["owasp"],

        meta["cwe"]

    ]

    result["message"]={

        "text":meta["title"],

        "markdown":build_help(meta)

    }


def add_fixes(result, meta):

    result["fixes"]=[

        {

            "description":{

                "text":meta["fix"]

            }

        }

    ]


def add_relationship(rule, meta):

    rule["relationships"]=[

        {

            "target":{

                "id":meta["cwe"]

            },

            "kinds":[

                "superset"

            ]

        }

    ]