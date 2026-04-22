from googleapiclient.discovery import build, HttpError
from custom_types import google_metrics_info as types

# CHROME (ADMIN SDK)


def exec_request(request):
    try:
        response = request.execute()
        return response
    except HttpError as e:
        print(
            "Error response status code : {0}, reason : {1}".format(
                e.status_code, e.error_details
            )
        )


# TODO: Check all of these functions to make sure they work properly, this is just a model


def check_ignore_certificate_warning(collection, user_id):
    request = collection.list(
        applicationName="chrome", event_type="UNSAFE_SITE_VISIT"
    )
    response = exec_request(request)

    events = response["activities"]
    return events


def check_reuse_password(collection, user_id):
    request = collection.list(
        applicationName="chrome", event_type="PASSWORD_REUSE"
    )
    response = exec_request(request)

    events = response["activities"]
    return events


def check_device_platform(collection, user_id):
    request = collection.list(
        applicationName="chrome",
        event_type="LOGIN_EVENT",
        parameter="DEVICE_PLATFORM",
    )
    response = exec_request(request)

    events = response["activities"]
    return events


def check_file_downloads(collection, user_id):
    request = collection.list(
        applicationName="chrome", event_type="CONTENT_TRANSFER"
    )
    # TODO: Se filtra por TRIGGER_TYPE=FILE_DOWNLOAD y luego se revisa el parámetro CONTENT_TYPE
    response = exec_request(request)

    # TODO: Añadir IF statement que depende de si la descarga tiene un tipo de riesgo o no, se incluye
    dangerous_file_types = [".exe", ".bat", ".cmd", ".ps1"]
    events = response["activities"]
    return events


def check_malware_download(collection, user_id):
    request = collection.list(
        applicationName="chrome", event_type="MALWARE_TRANSFER"
    )
    response = exec_request(request)

    # TODO: Filtrar por EVENT_REASON=MALWARE_TRANSFER_DANGEROUS_FILE

    events = response["activities"]
    return events


def check_vulnerable_password(collection, user_id):
    request = collection.list(
        applicationName="chrome", event_type="PASSWORD_BREACH"
    )
    response = exec_request(request)

    events = response["activities"]
    return events


def extract_files_with_full_access(collection, user_id):
    request = collection.list(
        q="visibility='anyoneWithLink'",
        spaces="drive",
        pageSize=10,
        fields="files(id, name, mimeType)",
    )

    files = []
    while request is not None:
        response = exec_request(request)
        files += response["files"]
        request = collection.list_next(request, response)

    return files


def extract_files_with_expiration_date(collection, user_id):
    request = collection.list(
        spaces="drive",
        pageSize=50,
        fields="files(id, name, permissions/expirationTime)",
    )

    files = []

    while request is not None:
        response = exec_request(request)
        files += response["files"]
        request = collection.list_next(request, response)

    return files


def extract_messages_sent_in_confidential_mode(collection, user_id):
    request = collection.list(
        q="from:me AND label:confidentialmode",
        pageSize=10,
        fields="messages(id)",
    )

    messages = []

    while request is not None:
        response = exec_request(request)
        messages += response["messages"]
        request = collection.list_next(request, response)

    return messages


def request_admin_sdk(users: list) -> dict[int, types.UserMetrics]:
    with build("admin", "reports_v1") as admin_service:
        activities_collection = admin_service.activities()

        user_info = {}
        for user in users:
            user_id = user["id"]
            user_metrics: types.UserMetrics = {}
            user_metrics["ignore_cert_warning"] = len(
                check_ignore_certificate_warning(
                    activities_collection, user_id
                )
            )
            user_metrics["reused_passwords"] = len(
                check_reuse_password(activities_collection, user_id)
            )
            user_metrics["device_platform"] = len(
                check_device_platform(activities_collection, user_id)
            )
            user_metrics["dangerous_files"] = check_file_downloads(
                activities_collection, user_id
            )
            user_metrics["malware_download"] = check_malware_download(
                activities_collection, user_id
            )
            user_metrics["vulnerable_password"] = check_vulnerable_password(
                activities_collection, user_id
            )
            user_info[user_id] = user_metrics
    return user_info


def request_drive(users: list) -> dict[int, types.UserMetrics]:
    with build("drive", "v3") as drive_service:
        files_collection = drive_service.files()

        # TODO: Obtain users from the Google DB?
        user_info = {}
        for user in users:
            user_id = user["id"]
            user_metrics: types.UserMetrics = {}
            user_metrics["full_access_files"] = len(
                extract_files_with_full_access(files_collection, user_id)
            )
            user_metrics["files_with_exp_date"] = len(
                extract_files_with_expiration_date(files_collection, user_id)
            )
            user_info[user_id] = user_metrics

        return user_info


def request_gmail(users: list):
    with build("gmail", "v1") as gmail_service:
        messages_collection = gmail_service.users().messages()

        user_info = {}
        for user in users:
            user_id = user["id"]
            user_metrics: types.UserMetrics = {}
            user_metrics["confidential_messages"] = len(
                extract_messages_sent_in_confidential_mode(
                    messages_collection, user_id
                )
            )
            user_info[user_id] = user_metrics
    return user_info


def fetch_api_data():
    return


# TODO: Ask Gemini about the hierchical structure of my functions and how adequate it is, in case I have to fix it
# TODO: Find books about prompt engineering, clean code, interfaces, etc.
# TODO: Define data models for all of these functions (create TypedDicts for them)
# TODO: Reflect this model somehow in the memory
