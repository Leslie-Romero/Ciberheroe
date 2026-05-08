from database.base import DBClientBase
from custom_types import DBUserGoogleMetrics


class GoogleDBClient(DBClientBase):
    def __init__(self, db_client, logger):
        super().__init__(db_client, logger)

    def insert_metrics(self, metrics: DBUserGoogleMetrics):
        self.insert_db_data("google_metrics", metrics)
        self.logger("Insertadas las métricas de Google para cada usuario")
