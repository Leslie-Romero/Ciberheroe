# google_base.py
from googleapiclient.errors import HttpError


class GoogleAPIBase:
    """Parent class that holds shared logic for all Google APIs."""

    def exec_request(self, request):
        """Se encarga de ejecutar cualquier solicitud a las APIs de Google"""
        try:
            response = request.execute()
            return response
        except HttpError as e:
            print(
                "Error response status code : {0}, reason : {1}".format(
                    e.status_code, e.error_details
                )
            )
