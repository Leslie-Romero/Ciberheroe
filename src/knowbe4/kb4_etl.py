import logging
import uuid
from datetime import datetime, timezone
from dateutil.relativedelta import relativedelta
import pytz

import db
import config.env_config as config
from knowbe4 import (
    fetch_graph_api_data,
    fetch_rest_api_data,
    calculate_scores,
    get_historical_data,
    kb4_admin_metrics,
    kb4_basic_metrics,
    save_json,
)
from custom_types import (
    PasswordIQUser,
    User,
    CampaignRecipient,
    PhishingCampaignRun,
    DBMonthlyRisk,
    YearlyEnrollment,
)

logger = logging.getLogger(f"ciberheroe.{__name__}")

# TODO: Optimize this function


def kb4_integration():

    db_client = db.initialize_supabase_client()

    # Test conexión con supabase y obtenemos la ventana activa
    db_read_achievement_info = db.read_db_data(
        db_client, "kb4_achievement_info", "tag, points"
    )

    achievement_info = {
        row["tag"]: row["points"] for row in db_read_achievement_info
    }

    # Ventana activa para el filtrado por fecha
    active_window = achievement_info["ACTIVE_WINDOW"]

    n_users, n_psts = fetch_rest_api_data()

    api_psts, user_info, pwd_user_events, year_enrollments, assessment = (
        fetch_graph_api_data(n_users, n_psts)
    )

    users: list[User] = user_info["users"]["nodes"]
    active_users = {user["id"] for user in users}

    # check_histories(users)

    recipients: list[CampaignRecipient] = list()
    psts: list[PhishingCampaignRun] = list()
    for pst in api_psts["phishingCampaignRuns"]["nodes"]:
        psts.append(pst)
        recipients += [
            recipient
            for recipient in pst["campaignRecipients"]
            if recipient["user"]["id"] in active_users
        ]

    user_pwds: list[PasswordIQUser] = pwd_user_events["passwordIqUserStates"][
        "users"
    ]

    yearly_completed_enrollments: list[YearlyEnrollment] = year_enrollments[
        "enrollments"
    ]["nodes"]

    # 1. Porcentaje promedio de usuarios phish-prone
    phish_prone_percentage = kb4_basic_metrics.phish_prone_percentage(psts)

    # 2. Porcentaje de denuncias de phishing (simuladas)
    phishing = kb4_basic_metrics.phishing_reports(psts)

    # 3. Usuarios con más formaciones realizadas (top 5)
    top_educated, sorted_enrollments = kb4_basic_metrics.most_educated(
        users, yearly_completed_enrollments, 5
    )

    # 4. Porcentaje de clicks y denuncias por usuario en
    # simulaciones de phishing
    clicks_percentages, report_percentages, raw_metrics = (
        kb4_basic_metrics.click_percentage(recipients, users, active_window)
    )

    # 5. Plantillas de phishing con mayor tasa de éxitoç
    best_templates, monthly_clicks = kb4_basic_metrics.best_phishing_templates(
        recipients, 10, active_window
    )

    # 6. Usuarios con menor riesgo (KSAT)
    low_risk = kb4_basic_metrics.lowest_risk_users(10, users)

    # Inserción de datos históricos a falta de datos del último mes
    if config.HISTORICAL_DATA:
        historical_data = get_historical_data(users)
        db_monthly_risk_hist: list[DBMonthlyRisk] = list()
        for record in historical_data:
            db_monthly_risk_hist.append(
                {
                    "id": str(uuid.uuid4()),
                    "user_id": int(record["user_id"]),
                    "risk_score": float(record["risk_score"]),
                    "created_at": "2024-12-01",
                }
            )
        save_json({"data": db_monthly_risk_hist}, "historical_data")
        db.insert_db_data(
            db_client,
            "kb4_monthly_risk",
            db_monthly_risk_hist,
            "user_id, created_at",
        )
        logger.info("Insertamos los historicos para diciembre de 2024")

    # Obtenemos el riesgo del mes anterior
    now = datetime.now(pytz.utc).replace(
        day=1, hour=0, minute=0, second=0, microsecond=0
    )
    ref_date = now - relativedelta(months=1)
    if ref_date < pytz.utc.localize(datetime(2025, 11, 1)):
        ref_date = pytz.utc.localize(datetime(2024, 12, 1))
    db_last_risk = db.read_db_data(
        db_client,
        "kb4_monthly_risk",
        "user_id, risk_score",
        "created_at",
        ref_date.isoformat(),
    )

    # Cálculo de puntuaciones

    current_time = datetime.now(timezone.utc).replace(
        day=1, hour=0, minute=0, second=0, microsecond=0
    )
    last_month = current_time - relativedelta(months=1)

    # Leemos las puntuaciones de los últimos seis meses
    # para sumar a las de este mes
    db_last_semester_scores = db.read_last_semester_scores(
        db_client, "updated_at", "kb4_user_score_history"
    )

    db_score_data = {user["id"]: 0 for user in users}
    if db_last_semester_scores != list():
        db_score_data = {
            score["user_id"]: score["total_score"]
            for score in db_last_semester_scores
        }

    top10_month_templates, m = kb4_basic_metrics.best_phishing_templates(
        recipients,
        10,
        active_window,
        (current_time, (last_month.month, last_month.year)),
    )
    user_scores, user_score_history = calculate_scores(
        users,
        yearly_completed_enrollments,
        recipients,
        top10_month_templates,
        db_score_data,
        achievement_info,
        db_last_risk,
        active_window,
    )

    # db.save_score_history(db_client, users, user_score_history)

    # Métricas adicionales (mensual y anual)
    user_reports = kb4_basic_metrics.get_reporting_users(
        recipients, active_users, n_users, active_window
    )
    user_education = kb4_basic_metrics.get_educated_users(
        yearly_completed_enrollments, active_window, n_users
    )
    enrollments = kb4_basic_metrics.get_year_enrollments(users)

    # Vulnerabilidades
    vulnerable_users = kb4_admin_metrics.get_vulnerable_users(
        users, yearly_completed_enrollments, raw_metrics, recipients
    )

    pwds_detections_per_user, pwds = kb4_admin_metrics.get_vulnerable_pwd(
        user_pwds, users
    )

    assessment_results = kb4_admin_metrics.get_assessment_results(assessment)

    # Rellenamos la base de datos
    db.fill_db_user_info(
        db_client,
        active_window,
        users,
        sorted_enrollments,
        report_percentages,
        clicks_percentages,
        raw_metrics,
        user_scores,
        user_score_history,
    )

    db.fill_db_basic_metrics(
        db_client,
        best_templates,
        phish_prone_percentage,
        phishing,
        user_education[0],
        user_reports[0],
        user_education[1],
        user_reports[1],
        user_education[2],
        user_reports[2],
        top_educated,
        low_risk,
        enrollments,
    )

    db.fill_db_vulnerable_data(
        db_client,
        vulnerable_users,
        pwds,
        pwds_detections_per_user,
        assessment_results,
    )
