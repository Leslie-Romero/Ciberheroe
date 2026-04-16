from googleapiclient.discovery import build, HttpError

drive_service = build("drive", "v3")
files_collection = drive_service.files()
request = files_collection.list(q="visibility='anyoneWithLink'")
try:
    response = request.execute()
except HttpError as e:
    print(
        "Error response status code : {0}, reason : {1}".format(
            e.status_code, e.error_details
        )
    )

shared_files = request["files"]

# TODO: Check how to use the nextPageToken to read al results and accumulate them into a single list

drive_service.close()
