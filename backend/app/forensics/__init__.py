import re


AUTH_PATTERN = re.compile(
    r"\b(spf|dkim|dmarc)=(pass|fail|softfail|neutral|none|temperror|permerror)\b",
    re.IGNORECASE
)


def analyze_authentication(authentication_results):
    """
    Analyze SPF, DKIM and DMARC results from
    the Authentication-Results header.
    """

    result = {
        "spf": {
            "result": "unknown",
            "status": "not_available"
        },
        "dkim": {
            "result": "unknown",
            "status": "not_available"
        },
        "dmarc": {
            "result": "unknown",
            "status": "not_available"
        }
    }

    if not authentication_results:
        return result

    matches = AUTH_PATTERN.findall(authentication_results)

    for method, value in matches:

        method = method.lower()
        value = value.lower()

        result[method]["result"] = value

        if value == "pass":
            result[method]["status"] = "pass"

        elif value in ["fail", "softfail", "permerror"]:
            result[method]["status"] = "suspicious"

        elif value in ["neutral", "none", "temperror"]:
            result[method]["status"] = "inconclusive"

    return result