import ipaddress
import socket

import requests


# ============================================================
# IP CLASSIFICATION
# ============================================================

def classify_ip(ip: str) -> dict:
    """
    Classify an IP address as public, private,
    loopback, reserved, multicast, etc.
    """

    result = {
        "ip": ip,
        "valid": False,
        "version": None,
        "public": False,
        "private": False,
        "reserved": False,
        "loopback": False,
        "multicast": False,
        "unspecified": False,
        "documentation": False,
        "type": "UNKNOWN"
    }

    try:
        address = ipaddress.ip_address(ip)

    except ValueError:
        return result

    result["valid"] = True
    result["version"] = address.version
    result["public"] = address.is_global
    result["private"] = address.is_private
    result["reserved"] = address.is_reserved
    result["loopback"] = address.is_loopback
    result["multicast"] = address.is_multicast
    result["unspecified"] = address.is_unspecified

    # RFC documentation/test ranges
    if address.version == 4:

        documentation_ranges = [
            ipaddress.ip_network(
                "192.0.2.0/24"
            ),
            ipaddress.ip_network(
                "198.51.100.0/24"
            ),
            ipaddress.ip_network(
                "203.0.113.0/24"
            )
        ]

        result["documentation"] = any(
            address in network
            for network in documentation_ranges
        )

    if result["documentation"]:
        result["type"] = "DOCUMENTATION"

    elif result["loopback"]:
        result["type"] = "LOOPBACK"

    elif result["private"]:
        result["type"] = "PRIVATE"

    elif result["multicast"]:
        result["type"] = "MULTICAST"

    elif result["reserved"]:
        result["type"] = "RESERVED"

    elif result["unspecified"]:
        result["type"] = "UNSPECIFIED"

    elif result["public"]:
        result["type"] = "PUBLIC"

    return result


# ============================================================
# REVERSE DNS
# ============================================================

def reverse_dns(ip: str) -> dict:
    """
    Perform reverse DNS lookup.
    """

    result = {
        "available": False,
        "hostname": None,
        "error": None
    }

    try:

        hostname, aliases, addresses = (
            socket.gethostbyaddr(ip)
        )

        result["available"] = True
        result["hostname"] = hostname

    except socket.herror as exc:

        result["error"] = (
            f"Reverse DNS lookup failed: {exc}"
        )

    except socket.gaierror as exc:

        result["error"] = (
            f"Reverse DNS lookup failed: {exc}"
        )

    except Exception as exc:

        result["error"] = (
            f"Reverse DNS error: {exc}"
        )

    return result


# ============================================================
# IP GEOLOCATION
# ============================================================

def geolocate_ip(ip: str) -> dict:
    """
    Query a public IP geolocation service.

    This provides probable network/infrastructure
    location, NOT exact attacker location.
    """

    result = {
        "available": False,
        "country": None,
        "country_code": None,
        "region": None,
        "city": None,
        "latitude": None,
        "longitude": None,
        "organization": None,
        "asn": None,
        "timezone": None,
        "error": None
    }

    try:

        response = requests.get(
            f"https://ipwho.is/{ip}",
            timeout=8
        )

        if response.status_code != 200:

            result["error"] = (
                f"Geolocation returned HTTP "
                f"{response.status_code}"
            )

            return result

        data = response.json()

        if not data.get("success", False):

            result["error"] = data.get(
                "message",
                "Geolocation lookup failed"
            )

            return result

        result["available"] = True

        result["country"] = data.get(
            "country"
        )

        result["country_code"] = data.get(
            "country_code"
        )

        result["region"] = data.get(
            "region"
        )

        result["city"] = data.get(
            "city"
        )

        result["latitude"] = data.get(
            "latitude"
        )

        result["longitude"] = data.get(
            "longitude"
        )

        result["organization"] = data.get(
            "connection",
            {}
        ).get(
            "org"
        )

        result["asn"] = data.get(
            "connection",
            {}
        ).get(
            "asn"
        )

        result["timezone"] = data.get(
            "timezone",
            {}
        ).get(
            "id"
        )

    except requests.RequestException as exc:

        result["error"] = (
            f"Geolocation request failed: {exc}"
        )

    except ValueError as exc:

        result["error"] = (
            f"Invalid geolocation response: {exc}"
        )

    except Exception as exc:

        result["error"] = (
            f"Geolocation error: {exc}"
        )

    return result


# ============================================================
# SINGLE IP ANALYSIS
# ============================================================

def analyze_ip(
    ip: str,
    use_geolocation: bool = True
) -> dict:
    """
    Perform complete IP intelligence analysis.

    Geolocation is skipped for non-public/documentation
    addresses because those addresses do not represent
    useful public infrastructure location.
    """

    classification = classify_ip(
        ip
    )

    result = {
        "ip": ip,
        "classification": classification,
        "reverse_dns": {
            "available": False,
            "hostname": None,
            "error": "Skipped"
        },
        "geolocation": {
            "available": False,
            "country": None,
            "country_code": None,
            "region": None,
            "city": None,
            "latitude": None,
            "longitude": None,
            "organization": None,
            "asn": None,
            "timezone": None,
            "error": "Skipped"
        }
    }

    if not classification["valid"]:
        return result

    # --------------------------------------------------------
    # Reverse DNS
    # --------------------------------------------------------

    result["reverse_dns"] = reverse_dns(
        ip
    )

    # --------------------------------------------------------
    # Geolocation
    # --------------------------------------------------------

    if (
        use_geolocation
        and classification["public"]
        and not classification["documentation"]
    ):

        result["geolocation"] = (
            geolocate_ip(ip)
        )

    elif classification["documentation"]:

        result["geolocation"]["error"] = (
            "Documentation/test IP; "
            "real infrastructure geolocation not applicable"
        )

    elif classification["private"]:

        result["geolocation"]["error"] = (
            "Private IP; public geolocation not applicable"
        )

    else:

        result["geolocation"]["error"] = (
            "Non-public IP; geolocation skipped"
        )

    return result


# ============================================================
# MULTIPLE IPs
# ============================================================

def analyze_ips(
    ips: list[str],
    use_geolocation: bool = True
) -> list[dict]:
    """
    Analyze multiple unique IP addresses.
    """

    if not ips:
        return []

    unique_ips = list(
        dict.fromkeys(
            ips
        )
    )

    return [
        analyze_ip(
            ip,
            use_geolocation=use_geolocation
        )
        for ip in unique_ips
    ]