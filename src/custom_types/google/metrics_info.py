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
    ignore_cert_warning: int
    reused_passwords: int
    device_platform: list[str]
    dangerous_files: int
    malware_download: int
    vulnerable_password: int
    two_step_ver: bool
    non_corporate_devices: bool
    full_access_files: int
    files_with_exp_date: int
    confidential_messages: int
