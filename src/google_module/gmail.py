from google_module.base import GoogleAPIBase
from google.oauth2 import service_account
from googleapiclient.discovery import build
from config import env_config as config

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

base_creds = service_account.Credentials.from_service_account_file(
    config.SERVICE_ACCOUNT_FILE, scopes=SCOPES
)


class GmailExtractor(GoogleAPIBase):
    def __init__(self, user_email):
        user_credentials = base_creds.with_subject(user_email)

        self.service = build("gmail", "v1", credentials=user_credentials)
        self.messages_collection = self.service.users().messages()

    def extract_messages_sent_in_confidential_mode(self):
        """Extrae los correos enviados en modo confidencial"""
        request = self.messages_collection.list(
            userId="me",
            q="from:me AND label:confidentialmode",
            maxResults=10,
            fields="messages(id)",
        )

        messages = []

        while request is not None:
            response = self.exec_request(request)
            if response != {}:
                messages += response["messages"]
            request = self.messages_collection.list_next(request, response)

        return messages
