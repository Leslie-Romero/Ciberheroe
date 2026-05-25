from custom_types import GoogleUserMetrics, DBGooglePointSystem
from collections import defaultdict
from typing import cast


class GoogleScoreCalculator:

    def process_devices(self, user_devices) -> tuple[int, float]:
        non_corp_devices = set()
        platform = defaultdict(lambda: 0)
        for device in user_devices:
            if device["ownership"] == "BYOD":
                non_corp_devices.add(device["device_id"])
            platform[device["platform"]] += 1

        windows = platform.get("WINDOWS", 0)
        all_platforms = sum(value for key, value in platform.items())
        total = 1 if all_platforms == 0 else all_platforms

        return len(non_corp_devices), (windows / total)

    def calculate_scores(
        self,
        user_metrics: GoogleUserMetrics,
        points: list[DBGooglePointSystem],
    ) -> float:
        user_score = 0
        processed_points = {elem["label"]: elem["points"] for elem in points}
        for label, value in user_metrics.items():
            user_score += processed_points.get(label, 0) * cast(
                float | int | bool, value
            )
        return user_score
