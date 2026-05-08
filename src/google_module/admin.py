from google_module.base import GoogleAPIBase
from google.oauth2 import service_account
from googleapiclient.discovery import build
from config import env_config as config
from datetime import datetime, timezone, timedelta
import os
from collections import defaultdict

SCOPES = [
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
]

# Falta añadir este SCOPE
# "https://www.googleapis.com/auth/admin.directory.device.mobile.readonly",

admin_creds = service_account.Credentials.from_service_account_file(
    config.SERVICE_ACCOUNT_FILE, scopes=SCOPES, subject=config.SUBJECT_EMAIL
)


class AdminDirectoryExtractor(GoogleAPIBase):
    def __init__(self, domain="satocan.com"):
        self.service = build("admin", "directory_v1", credentials=admin_creds)
        self.users_collection = self.service.users()
        self.mobiledevices_collecion = self.service.mobiledevices()
        self.domain = domain

    def extract_user_list(self):
        # Extracts both the user list and the 2SV
        request = self.users_collection.list(
            domain=self.domain, fields="users(primaryEmail, isEnrolledIn2Sv)"
        )

        print("Request:", request)

        users = []
        while request is not None:
            response = self.exec_request(request)
            if response != {}:
                users += response["users"]
            request = self.users_collection.list_next(request, response)

        return users

    def check_device_platform(self):
        request = self.mobiledevices_collecion.list(
            customerId="my_customer",
            maxResults=100,
            projection="FULL",
        )
        devices = defaultdict(lambda: {"devices": []})
        while request is not None:
            response = self.exec_request(request)
            for device in response.get("mobiledevices", []):
                owner = device.get("email", ["no_email_found"])[0]
                devices[owner]["devices"].append(device)
            request = self.activities_collection.list_next(request, response)
        return devices


class AdminReportsExtractor(GoogleAPIBase):
    def __init__(self, days_start: float = 7):
        self.service = build("admin", "reports_v1", credentials=admin_creds)
        self.activities_collection = self.service.activities()
        start_time = datetime.now(timezone.utc) - timedelta(days=7)
        self.start_time_string = start_time.isoformat().replace("+00:00", "Z")

    def check_ignore_certificate_warning(self):
        """Revisa si se han visitado páginas no seguras en los últimos días"""
        request = self.activities_collection.list(
            userKey="all",
            applicationName="chrome",
            eventName="UNSAFE_SITE_VISIT",
            startTime=self.start_time_string,
        )
        events = []
        while request is not None:
            response = self.exec_request(request)
            events = response.get("items", [])
            request = self.activities_collection.list_next(request, response)

        return events

    def check_reuse_password(self):
        """Revisa si el usuario tiene contraseñas reutilizadas"""
        request = self.activities_collection.list(
            userKey="all",
            applicationName="chrome",
            eventName="PASSWORD_REUSE",
            startTime=self.start_time_string,
        )
        events = []
        while request is not None:
            response = self.exec_request(request)
            events = response.get("items", [])
            request = self.activities_collection.list_next(request, response)

        return events

    def check_file_downloads(
        self,
        dangerous_file_types={
            ".exe",
            ".bat",
            ".cmd",
            ".ps1",
            ".vbs",
            ".scr",
            ".msi",
            ".jar",
        },
    ):
        request = self.activities_collection.list(
            userKey="all",
            applicationName="chrome",
            eventName="CONTENT_TRANSFER",
            startTime=self.start_time_string,
            fields="items(actor, events(parameters))",
        )
        events = defaultdict(lambda: {"events": []})
        while request is not None:
            response = self.exec_request(request)
            items = response.get("items", [])
            for item in items:
                actor = item["actor"].get("email", "missing-email")
                for event in item.get("events", []):
                    download_event = next(
                        (
                            d.get("value")
                            for d in event.get("parameters")
                            if d.get("name") == "CONTENT_NAME"
                            and os.path.splitext(d.get("value"))[1]
                            in dangerous_file_types
                        ),
                        "No events",
                    )
                    if download_event == "No events":
                        continue
                    events[actor]["events"].append(download_event)
            request = self.activities_collection.list_next(request, response)

        return events

    def check_malware_download(self):
        request = self.activities_collection.list(
            userKey="all",
            applicationName="chrome",
            eventName="MALWARE_TRANSFER",
            startTime=self.start_time_string,
            fields="items(actor, events(parameters))",
        )
        response = self.exec_request(request)

        return response

        # TODO: Filtrar por EVENT_REASON=MALWARE_TRANSFER_DANGEROUS_FILE

        events = response.get("items", [])
        return events

    def check_vulnerable_password(self):
        """Revisa si el usuario tiene alguna contraseña vulnerada"""
        request = self.activities_collection.list(
            userKey="all",
            applicationName="chrome",
            eventName="PASSWORD_BREACH",
            startTime=self.start_time_string,
        )
        events = []
        while request is not None:
            response = self.exec_request(request)
            events = response.get("items", [])
            request = self.activities_collection.list_next(request, response)

        return events
