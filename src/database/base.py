from typing import Any, cast
from supabase import Client
from logging import Logger


class DBClientBase:
    """Base class for all clients interacting with the Database"""

    def __init__(self, db_client: Client, logger: Logger):
        self.db_client = db_client
        self.logger = logger

    def insert_db_data(self, table_name: str, data: Any, conflict: str = "id"):
        """Inserta datos en la base de datos"""
        try:
            response = (
                self.client.table(table_name)
                .upsert(cast(list[dict], data), on_conflict=conflict)
                .execute()
            )
            return response
        except Exception as e:
            self.logger.error(
                f"Ha ocurrido un error al intentar insertar los datos en la BD (tabla: {table_name}): {e}"
            )
            raise e
