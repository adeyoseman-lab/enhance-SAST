def cvss_to_level(score: float):

    if score >= 9.0:
        return "Critical", "error"

    if score >= 7.0:
        return "High", "error"

    if score >= 4.0:
        return "Medium", "warning"

    if score > 0:
        return "Low", "note"

    return "Informational", "note"