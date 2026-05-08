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

    # Falta añadir el SCOPE para los dispositivos
    # device_platforms = admin_directory.check_device_platform()
    # save_json(device_platforms, "device_platforms")

    admin_reports = AdminReportsExtractor()
    unsafe_sites = admin_reports.check_ignore_certificate_warning()
    save_json(unsafe_sites, "unsafe_sites")

    reuse_passwords = admin_reports.check_reuse_password()
    save_json(reuse_passwords, "reuse_passwords")

    file_downloads = admin_reports.check_file_downloads()
    save_json(file_downloads, "file_downloads")

    malware_download = admin_reports.check_malware_download()
    save_json(malware_download, "malware_download")

    vulnerable_passwords = admin_reports.check_vulnerable_password()
    save_json(vulnerable_passwords, "vulnerable_passwords")

    # Ejemplo
    email = "leslie.romero-practicas@satocan.com"

    drive = GoogleDriveExtractor(email)
    gmail = GmailExtractor(email)

    full_access = drive.extract_files_with_full_access()
    save_json(full_access, "drive_full_access")

    exp_date = drive.extract_files_with_expiration_date()
    save_json(exp_date, "drive_exp_date_files")

    conf_messages = gmail.extract_messages_sent_in_confidential_mode()
    save_json(conf_messages, "confidential_messages")

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
