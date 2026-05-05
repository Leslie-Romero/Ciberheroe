from google_module.base import GoogleAPIBase
from google.oauth2 import service_account
from googleapiclient.discovery import build
from config import env_config as config
from datetime import datetime, timezone, timedelta

SCOPES = [
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
]

admin_creds = service_account.Credentials.from_service_account_file(
    config.SERVICE_ACCOUNT_FILE, scopes=SCOPES, subject=config.SUBJECT_EMAIL
)


class AdminDirectoryExtractor(GoogleAPIBase):
    def __init__(self, domain="satocan.com"):
        self.service = build("admin", "directory_v1", credentials=admin_creds)
        self.users_collection = self.service.users()
        self.domain = domain

    def extract_user_list(self):
        # Se puede modificar después acorde a las necesidades (pasarlo por parámetro)
        request = self.users_collection.list(
            domain=self.domain, fields="users(primaryEmail)"
        )

        print("Request:", request)

        users = []
        while request is not None:
            response = self.exec_request(request)
            users += response["users"]
            request = self.files_collection.list_next(request, response)

        return users

    def check_2sv(self):
        # TODO: Finish query
        request = self.users_collection.list(domain=self.domain, fields="")

        results = []
        while request is not None:
            response = self.exec_request(request)
            results += response["users"]
            request = self.files_collection.list_next(request, response)

        return results


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
            events = response["activities"]
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
            events = response["activities"]
            request = self.activities_collection.list_next(request, response)

        return events

    def check_device_platform(self):
        request = self.activities_collection.list(
            userKey="all",
            applicationName="chrome",
            eventName="LOGIN_EVENT",
            startTime=self.start_time_string,
        )
        events = []
        # TODO: Falta añadir el post-procesado para buscar el parámetro DEVICE_PLATFORM
        while request is not None:
            response = self.exec_request(request)
            events = response["activities"]
            request = self.activities_collection.list_next(request, response)

        return events

    def check_file_downloads(
        self, dangerous_file_types=[".exe", ".bat", ".cmd", ".ps1"]
    ):
        # TODO: correct this function
        request = self.activities_collection.list(
            applicationName="chrome", event_type="CONTENT_TRANSFER"
        )
        # TODO: Se filtra por TRIGGER_TYPE=FILE_DOWNLOAD y luego se revisa el parámetro CONTENT_TYPE
        response = self.exec_request(request)

        # TODO: Añadir IF statement que depende de si la descarga tiene un tipo de riesgo
        events = response["activities"]
        return events

    def check_malware_download(self):
        # TODO: correct this function
        request = self.activities_collection.list(
            applicationName="chrome", event_type="MALWARE_TRANSFER"
        )
        response = self.exec_request(request)

        # TODO: Filtrar por EVENT_REASON=MALWARE_TRANSFER_DANGEROUS_FILE

        events = response["activities"]
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
            events = response["activities"]
            request = self.activities_collection.list_next(request, response)

        return events
