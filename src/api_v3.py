"""
This program is free software: you can redistribute it under the terms
of the GNU General Public License, v. 3.0. If a copy of the GNU General
Public License was not distributed with this file, see <https://www.gnu.org/licenses/>.
"""

import os
import json
from datetime import datetime
import calendar

from flask import Blueprint, request, jsonify
from flask_cors import CORS
from werkzeug.exceptions import BadRequest, NotFound

from phonenumbers import geocoder

from src.db import connect
from src.entity import fetch_all_entities
from src.utils import (
    decrypt_and_decode,
    validate_metrics_args,
    filter_dict,
    get_configs,
)
from src.user_metrics import get_signup_users, get_retained_users
from base_logger import get_logger

v3_blueprint = Blueprint("v3", __name__, url_prefix="/v3")
CORS(v3_blueprint)

database = connect()

logger = get_logger(__name__)

STATIC_KEYSTORE_PATH = get_configs("STATIC_X25519_KEYSTORE_PATH", strict=True)
DEFAULT_EXPORT_PATH = os.path.join(STATIC_KEYSTORE_PATH, "exported_public_keys.json")


def set_security_headers(response):
    """Set security headers for each response."""
    security_headers = {
        "Strict-Transport-Security": "max-age=63072000; includeSubdomains",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "script-src 'self'; object-src 'self'",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Cache-Control": "no-cache",
        "Permissions-Policy": (
            "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(), "
            "clipboard-read=(), clipboard-write=(), cross-origin-isolated=(), display-capture=(), "
            "document-domain=(), encrypted-media=(), execution-while-not-rendered=(), "
            "execution-while-out-of-viewport=(), fullscreen=(), gamepad=(), geolocation=(), "
            "gyroscope=(), magnetometer=(), microphone=(), midi=(), navigation-override=(), "
            "payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), "
            "speaker=(), speaker-selection=(), sync-xhr=(), usb=(), web-share=(), "
            "xr-spatial-tracking=()"
        ),
    }

    for header, value in security_headers.items():
        response.headers[header] = value

    return response


@v3_blueprint.before_request
def _db_connect():
    """Connect to the database before processing the request."""
    database.connect(reuse_if_open=True)


@v3_blueprint.teardown_request
def _db_close(response):
    """Close the database connection after processing the request."""
    database.close()
    return response


@v3_blueprint.after_request
def after_request(response):
    """Set security headers after each request."""
    response = set_security_headers(response)
    return response


def fetch_entities_by_month(result, start, end):
    """Fetch entities grouped by month."""
    new_start = datetime.min
    new_end = datetime(
        end.year, end.month, calendar.monthrange(end.year, end.month)[1], 23, 59, 59
    )

    entities = fetch_all_entities(date_range=(new_start, new_end))

    for entity in entities:
        entity_date_created = entity.date_created
        month_name = calendar.month_name[entity_date_created.month]

        result = update_result_by_time(result, entity_date_created, month_name)
        result = update_countries(result, entity)

    result["total_users"] = len(entities)
    result["total_countries"] = len(result["countries"])

    return result


def fetch_entities_by_day(result, start, end):
    """Fetch entities grouped by day."""
    new_start = datetime.min
    new_end = datetime(end.year, end.month, end.day, 23, 59, 59)

    entities = fetch_all_entities(date_range=(new_start, new_end))

    for entity in entities:
        entity_date_created = entity.date_created
        day_name = entity_date_created.strftime("%c")

        result = update_result_by_time(result, entity_date_created, day_name)
        result = update_countries(result, entity)

    result["total_users"] = len(entities)
    result["total_countries"] = len(result["countries"])

    return result


def update_result_by_time(result, entity_date_created, time_name):
    """Helper to update the result dictionary with time-based data."""
    year = str(entity_date_created.year)

    if not result.get(year):
        result[year] = []

    if any(time_name in x for x in result[year]):
        for x in result[year]:
            if x[0] == time_name:
                x[1] += 1
    else:
        result[year].append([time_name, 1])

    return result


def update_countries(result, entity):
    """Helper to update the result dictionary with country-based data."""
    region_code = decrypt_and_decode(entity.country_code)
    country_name = geocoder._region_display_name(region_code, "en")

    if any(country_name in x for x in result["countries"]):
        for x in result["countries"]:
            if x[0] == country_name and x[1] == region_code:
                x[2] += 1
    else:
        result["countries"].append([country_name, region_code, 1])

    return result


@v3_blueprint.route("/entities", methods=["GET"])
def get_entities_analysis():
    """Retrieve analysis of entities."""
    start = request.args.get("start")
    end = request.args.get("end")
    _format = request.args.get("format", "month")

    if not start or not end:
        raise BadRequest("Invalid input parameters. Provide 'start', 'end'.")

    start = datetime.strptime(start, "%Y-%m-%d").date()
    end = datetime.strptime(end, "%Y-%m-%d").date()

    if start > end:
        raise BadRequest("'start' date cannot be after 'end' date.")

    result = {"total_users": 0, "total_countries": 0, "countries": []}

    if _format == "month":
        result = fetch_entities_by_month(result, start, end)
    elif _format == "day":
        result = fetch_entities_by_day(result, start, end)
    else:
        raise BadRequest("Invalid format. Expected 'month' or 'day'.")

    logger.info("Successfully fetched entities data.")
    return jsonify(result), 200


@v3_blueprint.route("/metrics/signup", methods=["GET"])
def signup_users():
    """Endpoint to retrieve signup user data based on specified filters and grouping."""

    args = request.args
    filters = args.to_dict()

    group_by = args.get("group_by", type=str)
    top = args.get("top", type=int)
    has_pagination = top is None and group_by is not None

    options = {
        "granularity": args.get("granularity", type=str, default="day"),
        "top": top,
        "page": args.get("page", type=int, default=1) if has_pagination else None,
        "page_size": (
            args.get("page_size", type=int, default=50) if has_pagination else None
        ),
        "group_by": group_by,
    }

    combined_options = {**filters, **options}

    try:
        filtered_options = filter_dict(
            combined_options,
            include_only=("start_date", "end_date", "top", "page", "page_size"),
        )
        validate_metrics_args(**filtered_options)
    except ValueError as e:
        raise BadRequest(str(e)) from e

    try:
        result = get_signup_users(filters=filters, group_by=group_by, options=options)
    except ValueError as e:
        raise BadRequest(str(e)) from e

    logger.info("Successfully fetched signup metrics.")
    return jsonify(result)


@v3_blueprint.route("/metrics/retained", methods=["GET"])
def retained_users():
    """Endpoint to retrieve retained user data based on specified filters and grouping."""

    args = request.args
    filters = args.to_dict()

    group_by = args.get("group_by", type=str)
    top = args.get("top", type=int)
    has_pagination = top is None and group_by is not None

    options = {
        "granularity": args.get("granularity", type=str, default="day"),
        "top": top,
        "page": args.get("page", type=int, default=1) if has_pagination else None,
        "page_size": (
            args.get("page_size", type=int, default=50) if has_pagination else None
        ),
        "group_by": group_by,
    }

    combined_options = {**filters, **options}

    try:
        filtered_options = filter_dict(
            combined_options,
            include_only=("start_date", "end_date", "top", "page", "page_size"),
        )
        validate_metrics_args(**filtered_options)
    except ValueError as e:
        raise BadRequest(str(e)) from e

    try:
        result = get_retained_users(filters=filters, group_by=group_by, options=options)
    except ValueError as e:
        raise BadRequest(str(e)) from e

    logger.info("Successfully fetched retained metrics.")
    return jsonify(result)


@v3_blueprint.route("/keys/static-x25519", methods=["GET"])
def fetch_static_x25519_keys():
    """Fetch static x25519 public keys from a JSON file."""

    try:
        with open(DEFAULT_EXPORT_PATH, "r", encoding="utf-8") as file:
            static_keys = json.load(file)
    except FileNotFoundError as exc:
        logger.error("File not found: %s", DEFAULT_EXPORT_PATH)
        raise NotFound("Static public keys not found") from exc
    except json.JSONDecodeError as exc:
        logger.error("Invalid JSON format in file: %s", DEFAULT_EXPORT_PATH)
        raise BadRequest("Invalid key file format") from exc

    logger.info("Successfully retrieved static x25519 public keys.")
    return jsonify(static_keys)


@v3_blueprint.errorhandler(BadRequest)
@v3_blueprint.errorhandler(NotFound)
def handle_bad_request_error(error):
    """Handle BadRequest errors."""
    logger.error(error.description)
    return jsonify({"error": error.description}), error.code


@v3_blueprint.errorhandler(Exception)
def handle_generic_error(error):
    """Handle generic errors."""
    logger.exception(error)
    return (
        jsonify({"error": "Oops! Something went wrong. Please try again later."}),
        500,
    )
