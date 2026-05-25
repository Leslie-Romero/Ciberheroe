from google_module.base import GoogleAPIBase
from google.oauth2 import service_account
from googleapiclient.discovery import build
from config import env_config as config
from logging import Logger

SCOPES = ["https://www.googleapis.com/auth/drive.readonly"]

base_creds = service_account.Credentials.from_service_account_file(
    config.SERVICE_ACCOUNT_FILE, scopes=SCOPES
)


class GoogleDriveExtractor(GoogleAPIBase):
    def __init__(self, logger: Logger, user_email: str):

        user_credentials = base_creds.with_subject(user_email)

        self.service = build("drive", "v3", credentials=user_credentials)
        super().__init__(logger, self.service)
        self.files_collection = self.service.files()

    def extract_files_with_full_access(self):
        """Extrae los archivos cuya visibilidad sea para todas las personas con el link"""
        request = self.files_collection.list(
            q="visibility='anyoneWithLink'",
            spaces="drive",
            pageSize=10,
            fields="files(id, name, mimeType)",
        )

        files = []
        while request is not None:
            response = self.exec_request(request)
            if response is None:
                break
            files += response.get("files", [])
            request = self.files_collection.list_next(request, response)

        return files

    def extract_files_with_expiration_date(self):
        """Extrae los archivos que se hayan compartido durante un tiempo limitado"""
        request = self.files_collection.list(
            spaces="drive",
            pageSize=50,
            fields="files(id, name, permissions/expirationTime)",
        )

        files = []

        while request is not None:
            response = self.exec_request(request)
            if response is None:
                break
            files += response.get("files", [])
            request = self.files_collection.list_next(request, response)

        return files
