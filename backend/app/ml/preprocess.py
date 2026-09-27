from pathlib import Path
from email import policy
from email.parser import BytesParser
from typing import Any

import csv
import re


# ============================================================
# TRACE-AI EMAIL DATASET PREPROCESSOR
# ============================================================
#
# Converts raw SpamAssassin .eml files into a structured CSV
# dataset that can later be used for ML training.
#
# Labels:
#   0 = HAM / BENIGN
#   1 = SPAM
#
# IMPORTANT:
# Spam is not identical to phishing.
# This dataset is being used initially to validate the
# real-world email preprocessing and ML pipeline.
# ============================================================


BASE_DIR = Path(__file__).resolve().parents[2]

RAW_DIR = BASE_DIR / "datasets" / "raw"

HAM_DIR = RAW_DIR / "ham"

SPAM_DIR = RAW_DIR / "spam"

PROCESSED_DIR = (
    BASE_DIR
    / "datasets"
    / "processed"
)

OUTPUT_FILE = (
    PROCESSED_DIR
    / "spamassassin_dataset.csv"
)


# ============================================================
# DIRECTORY SETUP
# ============================================================

def ensure_directories() -> None:
    """
    Make sure the required dataset directories exist.
    """

    HAM_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    SPAM_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    PROCESSED_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


# ============================================================
# EMAIL TEXT EXTRACTION
# ============================================================

def extract_text_from_email(
    file_path: Path,
) -> dict[str, Any]:
    """
    Parse a raw .eml file and extract useful textual fields.
    """

    try:

        with file_path.open(
            "rb"
        ) as file:

            message = BytesParser(
                policy=policy.default
            ).parse(file)

    except Exception as error:

        return {
            "success": False,
            "subject": "",
            "body": "",
            "sender": "",
            "recipient": "",
            "error": str(error)
        }

    subject = str(
        message.get(
            "Subject",
            ""
        )
    )

    sender = str(
        message.get(
            "From",
            ""
        )
    )

    recipient = str(
        message.get(
            "To",
            ""
        )
    )

    body_parts = []

    # --------------------------------------------------------
    # Multipart message
    # --------------------------------------------------------

    if message.is_multipart():

        for part in message.walk():

            content_type = (
                part.get_content_type()
            )

            disposition = str(
                part.get(
                    "Content-Disposition",
                    ""
                )
            ).lower()

            # Ignore attachments.

            if "attachment" in disposition:
                continue

            if content_type in {
                "text/plain",
                "text/html"
            }:

                try:

                    content = (
                        part.get_content()
                    )

                    if content:

                        body_parts.append(
                            str(content)
                        )

                except Exception:
                    continue

    # --------------------------------------------------------
    # Single-part message
    # --------------------------------------------------------

    else:

        try:

            content = (
                message.get_content()
            )

            if content:

                body_parts.append(
                    str(content)
                )

        except Exception:
            pass

    body = "\n".join(
        body_parts
    )

    return {

        "success": True,

        "subject": subject,

        "body": body,

        "sender": sender,

        "recipient": recipient,

        "error": None
    }


# ============================================================
# TEXT CLEANING
# ============================================================

def clean_text(
    text: str,
) -> str:
    """
    Normalize email text for ML preprocessing.
    """

    if not isinstance(
        text,
        str
    ):
        return ""

    # Remove excessive whitespace.

    text = re.sub(
        r"\s+",
        " ",
        text
    )

    # Normalize URLs.

    text = re.sub(
        r"https?://\S+",
        " URL ",
        text,
        flags=re.IGNORECASE
    )

    # Normalize email addresses.

    text = re.sub(
        r"\b[\w.+-]+@[\w.-]+\.\w+\b",
        " EMAIL ",
        text
    )

    # Normalize long numeric strings.

    text = re.sub(
        r"\b\d{4,}\b",
        " NUMBER ",
        text
    )

    return text.strip()


# ============================================================
# BUILD ML TEXT
# ============================================================

def build_email_text(
    email_data: dict[str, Any],
) -> str:
    """
    Combine subject, sender and body into one ML text field.
    """

    subject = email_data.get(
        "subject",
        ""
    )

    sender = email_data.get(
        "sender",
        ""
    )

    body = email_data.get(
        "body",
        ""
    )

    combined = (
        f"Subject: {subject}\n"
        f"From: {sender}\n"
        f"Body: {body}"
    )

    return clean_text(
        combined
    )


# ============================================================
# PROCESS DIRECTORY
# ============================================================

def process_directory(
    directory: Path,
    label: int,
    label_name: str,
) -> list[dict[str, Any]]:
    """
    Process every email file inside a directory.
    """

    records = []

    if not directory.exists():

        return records

    files = [
        path
        for path
        in directory.rglob("*")
        if path.is_file()
    ]

    print(
        f"\nProcessing {label_name}: "
        f"{len(files)} files"
    )

    for index, file_path in enumerate(
        files,
        start=1
    ):

        email_data = (
            extract_text_from_email(
                file_path
            )
        )

        if not email_data[
            "success"
        ]:

            continue

        text = build_email_text(
            email_data
        )

        if not text:

            continue

        records.append({

            "filename": file_path.name,

            "label": label,

            "label_name": label_name,

            "subject": clean_text(
                email_data[
                    "subject"
                ]
            ),

            "sender": clean_text(
                email_data[
                    "sender"
                ]
            ),

            "text": text
        })

        # Progress every 100 emails.

        if index % 100 == 0:

            print(
                f"  processed: {index}"
            )

    print(
        f"  usable emails: "
        f"{len(records)}"
    )

    return records


# ============================================================
# SAVE CSV
# ============================================================

def save_dataset(
    records: list[dict[str, Any]],
) -> None:
    """
    Save processed email records as CSV.
    """

    if not records:

        raise ValueError(
            "No usable email records found."
        )

    fieldnames = [
        "filename",
        "label",
        "label_name",
        "subject",
        "sender",
        "text"
    ]

    with OUTPUT_FILE.open(
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        writer.writerows(
            records
        )


# ============================================================
# DATASET SUMMARY
# ============================================================

def dataset_summary(
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Generate basic dataset statistics.
    """

    benign_count = sum(
        1
        for record
        in records
        if record.get("label") == 0
    )

    spam_count = sum(
        1
        for record
        in records
        if record.get("label") == 1
    )

    return {

        "total": len(
            records
        ),

        "benign": benign_count,

        "spam": spam_count,

        "output_file": str(
            OUTPUT_FILE
        )
    }


# ============================================================
# MAIN
# ============================================================

def main() -> None:

    print(
        "\nTRACE-AI EMAIL DATASET PREPROCESSOR"
    )

    print(
        "===================================="
    )

    ensure_directories()

    # --------------------------------------------------------
    # Process HAM
    # --------------------------------------------------------

    ham_records = process_directory(
        HAM_DIR,
        label=0,
        label_name="HAM"
    )

    # --------------------------------------------------------
    # Process SPAM
    # --------------------------------------------------------

    spam_records = process_directory(
        SPAM_DIR,
        label=1,
        label_name="SPAM"
    )

    # --------------------------------------------------------
    # Combine
    # --------------------------------------------------------

    records = (
        ham_records
        + spam_records
    )

    if not records:

        print(
            "\nERROR:"
        )

        print(
            "No usable emails were found."
        )

        print(
            f"\nPut HAM emails in:"
            f"\n{HAM_DIR}"
        )

        print(
            f"\nPut SPAM emails in:"
            f"\n{SPAM_DIR}"
        )

        return

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    save_dataset(
        records
    )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    summary = dataset_summary(
        records
    )

    print(
        "\nDATASET CREATED"
    )

    print(
        "================"
    )

    print(
        f"Total emails : "
        f"{summary['total']}"
    )

    print(
        f"Benign/HAM   : "
        f"{summary['benign']}"
    )

    print(
        f"Spam         : "
        f"{summary['spam']}"
    )

    print(
        f"\nSaved to:"
        f"\n{summary['output_file']}"
    )

    print(
        "\nTRACE-AI PREPROCESSING COMPLETE"
    )


if __name__ == "__main__":
    main()