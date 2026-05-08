from typing import TypedDict


class DBUserGoogleMetrics(TypedDict):
    id: int
    user_id: int
    date: str
    unsafe_site: int
    reused_pwds: int
    device_platforms: list[str]
    risky_file_downloads: int
    malware_downloads: int
    enabled_2sv: bool
    use_of_non_corporate_devices: int
    files_with_public_link: int
    files_wih_exp_date: int
    messages_in_conf_mode: int


class DBGoogleUser(TypedDict):
    id: int
    email: str
    metrics: DBUserGoogleMetrics
