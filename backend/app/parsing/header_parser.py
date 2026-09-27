def extract_header_evidence(headers: dict) -> dict:
    """
    Extract forensic evidence from email headers.
    """

    return {
        "sender": headers.get("From"),
        "recipient": headers.get("To"),
        "reply_to": headers.get("Reply-To"),
        "return_path": headers.get("Return-Path"),
        "subject": headers.get("Subject"),
        "date": headers.get("Date"),
        "message_id": headers.get("Message-ID"),
        "received_chain": headers.get("Received", []),
        "authentication_results": headers.get(
            "Authentication-Results"
        )
    }