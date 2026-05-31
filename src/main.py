import logging
from logging.handlers import RotatingFileHandler
import traceback
from pathlib import Path

import db
import google_module
import events_module

logger = logging.getLogger("ciberheroe")
logger.setLevel(logging.INFO)

MAX_BYTES = 285 * 1024
BACKUP_COUNT = 2

if not logger.handlers:
    BASE_DIR = Path(__file__).resolve().parent
    LOG_FILE_PATH = BASE_DIR / "logs/knowbe4_integration.log"

    file_handler = RotatingFileHandler(
        LOG_FILE_PATH,
        maxBytes=MAX_BYTES,
        backupCount=BACKUP_COUNT,
    )
    formatter = logging.Formatter(
        fmt="""%(asctime)s - %(levelname)s - %(name)s: line %(lineno)d
         - %(message)s""",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)


def main():
    db_client = db.initialize_supabase_client()
    google_module.google_etl(db_client)
    events_module.events_etl(db_client)
    return


if __name__ == "__main__":
    try:
        main()
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
