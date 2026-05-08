from typing import TypedDict


class User(TypedDict):
    displayName: str
    kind: str
    me: bool
    permissionId: str
    emailAddress: str
    photoLink: str


class File(TypedDict):
    id: str
    name: str
    mimeType: str


class FileListResponse(TypedDict):
    files: list[File]


class UserMetrics(TypedDict):
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
