from knowbe4_module import save_json
import logging
import traceback

logger = logging.getLogger(f"ciberheroe.{__name__}")


def events_etl():
    # Llamar al extractor
    # Pasar datos a la calculadora de puntuaciones
    # Pasar información a la base de datos
    return


if __name__ == "__main__":
    try:
        events_etl()
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
