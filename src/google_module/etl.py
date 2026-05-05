from google_module import (
    AdminDirectoryExtractor,
    AdminReportsExtractor,
    GoogleDriveExtractor,
    GmailExtractor,
)
from knowbe4_module import save_json
import logging
import traceback

logger = logging.getLogger(f"ciberheroe.{__name__}")


def google_etl():
    admin_directory = AdminDirectoryExtractor()
    users = admin_directory.extract_user_list()
    save_json(users, "google_user_list")
    admin_reports = AdminReportsExtractor()
    # users = admin_directory.extract_user_list()

    # Ejemplo
    email = "leslie.romero-practicas@satocan.com"

    drive = GoogleDriveExtractor(email)
    gmail = GmailExtractor(email)

    full_access = drive.extract_files_with_full_access()
    save_json(full_access, "drive_full_access")
    conf_messages = gmail.extract_messages_sent_in_confidential_mode()

    return


# TODO: Find books about prompt engineering, clean code, interfaces, etc.
# TODO: Define data models for all of these functions (create TypedDicts for them)
# TODO: Reflect this model somehow in the memory


if __name__ == "__main__":
    try:
        google_etl()
        print("OK")
    except Exception as e:
        print(f"ERROR: {e}")
        logger.critical(
            f"""Ha ocurrido un error critico, se ha interrumpido la ejecucion:
              {e} \n {traceback.format_exc()}"""
        )
        raise SystemExit(1)
    finally:
        logging.shutdown()
