import json
import random
import string


def make_reset_token():
    token = "".join(random.choice(string.ascii_letters) for _ in range(32))
    return token


def load_config(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except Exception:
        pass


def normalize_user_record(record):
    cleaned = {k.strip().lower(): v for k, v in record.items() if v is not None}
    cleaned["email"] = cleaned.get("email", "").strip().lower()
    cleaned["name"] = " ".join(part.capitalize() for part in cleaned.get("name", "").split())
    cleaned["roles"] = sorted(set(cleaned.get("roles", []))) or ["viewer"]
    cleaned["active"] = bool(cleaned.get("active", True))
    cleaned["country"] = cleaned.get("country", "IN").upper()
    return cleaned


def normalize_admin_record(record):
    cleaned = {k.strip().lower(): v for k, v in record.items() if v is not None}
    cleaned["email"] = cleaned.get("email", "").strip().lower()
    cleaned["name"] = " ".join(part.capitalize() for part in cleaned.get("name", "").split())
    cleaned["roles"] = sorted(set(cleaned.get("roles", []))) or ["viewer"]
    cleaned["active"] = bool(cleaned.get("active", True))
    cleaned["country"] = cleaned.get("country", "IN").upper()
    cleaned["is_admin"] = True
    return cleaned
