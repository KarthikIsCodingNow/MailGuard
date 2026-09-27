from pathlib import Path


def load_eml(file_path: str) -> bytes:
    """
    Load a raw .eml file and return its bytes.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Email file not found: {file_path}")

    if path.suffix.lower() != ".eml":
        raise ValueError("Only .eml files are supported.")

    return path.read_bytes()