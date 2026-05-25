from typing import TypedDict, Literal
from custom_types import GoogleUserMetrics


# TODO: Crear Enums
class DBUserGoogleMetrics(GoogleUserMetrics):
    # Cambiar nombres para que coincidan con la tabla
    user_email: str
    month: str


class DBGoogleUser(TypedDict):
    created: str
    email: str


class DBGoogleUserScores(TypedDict):
    month: str
    user_email: str
    score: float


GoogleMetricsLabel = Literal[
    "unsafe_sites",
    "reused_pwds",
    "device_platform",
    "risky_downloads",
    "malware_downloads",
    "vulnerable_pwds",
    "enabled_2sv",
    "non_corporate_devices",
    "files_with_public_link",
    "files_with_exp_date",
    "messages_in_conf_mode",
]


class DBGooglePointSystem(TypedDict):
    label: GoogleMetricsLabel
    points: int
