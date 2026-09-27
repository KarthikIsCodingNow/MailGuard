import hashlib
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses


def parse_email(raw_email: bytes) -> dict:
    """
    Parse a raw .eml file and extract:

    - Email headers
    - Plain-text body
    - HTML body
    - Attachments
    - Attachment metadata
    - SHA-256 hashes
    """

    # ============================================================
    # PARSE RAW EMAIL
    # ============================================================

    message = BytesParser(
        policy=policy.default
    ).parsebytes(raw_email)

    # ============================================================
    # HEADER EXTRACTION
    # ============================================================

    headers = {}

    for key, value in message.items():
        headers[key] = str(value)

    # ============================================================
    # RESULT OBJECT
    # ============================================================

    result = {
        "headers": headers,
        "body": "",
        "html_body": "",
        "attachments": []
    }

    # ============================================================
    # WALK THROUGH MIME PARTS
    # ============================================================

    if message.is_multipart():

        for part in message.walk():

            content_type = part.get_content_type()

            disposition = (
                part.get_content_disposition()
            )

            # ----------------------------------------------------
            # ATTACHMENT
            # ----------------------------------------------------

            if disposition == "attachment":

                filename = part.get_filename()

                payload = (
                    part.get_payload(
                        decode=True
                    )
                    or b""
                )

                # SHA-256 hash
                sha256 = hashlib.sha256(
                    payload
                ).hexdigest()

                attachment = {
                    "filename": filename,
                    "content_type": content_type,
                    "size": len(payload),
                    "sha256": sha256
                }

                result[
                    "attachments"
                ].append(attachment)

                continue

            # ----------------------------------------------------
            # INLINE ATTACHMENT
            # ----------------------------------------------------

            if disposition == "inline":

                filename = part.get_filename()

                # Some inline MIME parts are actually
                # email body content, so only treat it
                # as an attachment when a filename exists.

                if filename:

                    payload = (
                        part.get_payload(
                            decode=True
                        )
                        or b""
                    )

                    sha256 = hashlib.sha256(
                        payload
                    ).hexdigest()

                    attachment = {
                        "filename": filename,
                        "content_type": content_type,
                        "size": len(payload),
                        "sha256": sha256
                    }

                    result[
                        "attachments"
                    ].append(attachment)

                    continue

            # ----------------------------------------------------
            # PLAIN TEXT BODY
            # ----------------------------------------------------

            if content_type == "text/plain":

                try:

                    content = part.get_content()

                except Exception:

                    payload = (
                        part.get_payload(
                            decode=True
                        )
                        or b""
                    )

                    content = payload.decode(
                        "utf-8",
                        errors="replace"
                    )

                if content:

                    result[
                        "body"
                    ] += str(content)

            # ----------------------------------------------------
            # HTML BODY
            # ----------------------------------------------------

            elif content_type == "text/html":

                try:

                    content = part.get_content()

                except Exception:

                    payload = (
                        part.get_payload(
                            decode=True
                        )
                        or b""
                    )

                    content = payload.decode(
                        "utf-8",
                        errors="replace"
                    )

                if content:

                    result[
                        "html_body"
                    ] += str(content)

    else:

        # ========================================================
        # NON-MULTIPART EMAIL
        # ========================================================

        content_type = (
            message.get_content_type()
        )

        try:

            content = message.get_content()

        except Exception:

            payload = (
                message.get_payload(
                    decode=True
                )
                or b""
            )

            content = payload.decode(
                "utf-8",
                errors="replace"
            )

        if content_type == "text/plain":

            result[
                "body"
            ] = str(content)

        elif content_type == "text/html":

            result[
                "html_body"
            ] = str(content)

    # ============================================================
    # CLEAN BODY TEXT
    # ============================================================

    result["body"] = (
        result["body"].strip()
    )

    result["html_body"] = (
        result["html_body"].strip()
    )

    # ============================================================
    # RETURN
    # ============================================================

    return result