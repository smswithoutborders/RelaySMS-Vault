"""OTP Service Module."""

import datetime
import random

from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException
from src.db_models import OTPRateLimit, OTP
from src.utils import get_configs
from src.sms_outbound import (
    get_phonenumber_region_code,
    send_with_queuedroid,
    QUEUEDROID_SUPPORTED_VERIFICATION_REGION_CODES,
)
from base_logger import get_logger

logger = get_logger(__name__)

TWILIO_ACCOUNT_SID = get_configs("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = get_configs("TWILIO_AUTH_TOKEN")
TWILIO_SERVICE_SID = get_configs("TWILIO_SERVICE_SID")
TWILIO_PHONE_NUMBER = get_configs("TWILIO_PHONE_NUMBER")
MOCK_OTP = get_configs("MOCK_OTP")
MOCK_OTP = MOCK_OTP.lower() == "true" if MOCK_OTP is not None else False
DUMMY_PHONENUMBERS = get_configs(
    "DUMMY_PHONENUMBER", default_value="+237123456789"
).split(",")

OTP_ENABLED = get_configs("OTP_ENABLED", default_value="true")
OTP_ENABLED = OTP_ENABLED.lower() == "true" if OTP_ENABLED is not None else True
OTP_ALLOWED_COUNTRIES = get_configs("OTP_ALLOWED_COUNTRIES")
OTP_ALLOWED_COUNTRIES = [
    c.strip().strip("'\"").upper()
    for c in (OTP_ALLOWED_COUNTRIES or "").strip("[]").split(",")
    if c
]
RATE_LIMIT_WINDOWS = [
    {"duration": 5, "count": 1},  # 5 minute window
    {"duration": 10, "count": 2},  # 10 minute window
    {"duration": 30, "count": 3},  # 30 minute window
    {"duration": 120, "count": 4},  # 2 hour window
]


def is_rate_limited(phone_number):
    """
    Check if the provided phone number has exceeded the rate limit
    for OTP (One-Time Password) requests.

    Args:
        phone_number (str): The phone number to check.

    Returns:
        bool: True if the phone number is rate limited, False otherwise.
    """
    logger.debug("Checking rate limit for phone number...")
    current_time = datetime.datetime.now()
    rate_limit = OTPRateLimit.get_or_none(OTPRateLimit.phone_number == phone_number)

    if rate_limit:
        clean_rate_limit_store(phone_number)
        index = next(
            (
                i
                for i, window in enumerate(RATE_LIMIT_WINDOWS)
                if window["count"] == rate_limit.attempt_count
            ),
            -1,
        )

        if rate_limit.date_expires >= current_time:
            logger.info(
                "Rate limit exceeded in %s-minute window.",
                RATE_LIMIT_WINDOWS[index]["duration"],
            )
            return True
    return False


def send_otp(phone_number, message_body=None):
    """
    Sends a One-Time Password (OTP) to the specified phone number.

    Args:
        phone_number (str): The recipient's phone number in E.164 format (e.g., "+1234567890").
        message_body (str, optional): A custom message body for the OTP.

    Returns:
        tuple:
            - bool: True if the OTP was sent successfully, False otherwise.
            - str: A message indicating the result of the OTP sending process.
            - int or None: The OTP expiry time as a Unix timestamp if the OTP was sent successfully;
              otherwise, None.
    """
    logger.debug("Sending OTP to phone number...")

    if not OTP_ENABLED:
        logger.info("OTP service is currently disabled")
        return (
            False,
            "OTP service is temporarily unavailable. Please try again later or contact support.",
            None,
        )

    region_code = get_phonenumber_region_code(phone_number)
    if OTP_ALLOWED_COUNTRIES and region_code not in OTP_ALLOWED_COUNTRIES:
        logger.info("OTP not allowed for country: %s", region_code)
        return (
            False,
            "OTP service is not available for your region. Please contact support for assistance.",
            None,
        )

    if is_rate_limited(phone_number):
        return False, "Too many OTP requests. Please wait and try again later.", None

    expires = None

    if MOCK_OTP:
        success, message = mock_send_otp()
    elif phone_number in DUMMY_PHONENUMBERS:
        success, message = mock_send_otp()
    elif region_code in QUEUEDROID_SUPPORTED_VERIFICATION_REGION_CODES:
        _, otp_result = create_inapp_otp(phone_number=phone_number)
        otp_code, _ = otp_result

        message_body = "Your RelaySMS Verification Code is: " + otp_code
        success = send_with_queuedroid(phone_number, message_body)
        message = (
            "OTP sent successfully. Please check your phone for the code."
            if success
            else "Failed to send OTP. Please try again later."
        )
    else:
        success, message = twilio_send_otp(phone_number, message_body)

    if success:
        otp = increment_rate_limit(phone_number)
        expires = int(otp.date_expires.timestamp())

    return success, message, expires


def verify_otp(phone_number, otp, use_twilio=True):
    """
    Verify the provided OTP for the given phone number.

    Args:
        phone_number (str): The phone number to verify the OTP for.
        otp (str): The OTP to verify.
        use_twilio (bool, optional): A flag to indicate whether to use
            Twilio for verification. Defaults to True.

    Returns:
        tuple: A tuple containing the following elements:
            - A boolean indicating whether the OTP was verified successfully.
            - A message indicating the result of the OTP verification process.
    """
    logger.debug("Verifying OTP for phone number...")

    if not OTP_ENABLED:
        logger.info("OTP service is currently disabled")
        return (
            False,
            "OTP service is temporarily unavailable. Please try again later or contact support.",
        )

    region_code = get_phonenumber_region_code(phone_number)
    if OTP_ALLOWED_COUNTRIES and region_code not in OTP_ALLOWED_COUNTRIES:
        logger.info("OTP not allowed for country: %s", region_code)
        return (
            False,
            "OTP service is not available for your region. Please contact support for assistance.",
        )

    if not OTPRateLimit.get_or_none(OTPRateLimit.phone_number == phone_number):
        return (
            False,
            "OTP not initiated. Please request a new OTP before attempting to verify.",
        )

    if MOCK_OTP:
        success, message = mock_verify_otp(otp)
    elif phone_number in DUMMY_PHONENUMBERS:
        success, message = mock_verify_otp(otp)
    elif region_code in QUEUEDROID_SUPPORTED_VERIFICATION_REGION_CODES:
        success, message = verify_inapp_otp(phone_number, otp)
    elif use_twilio:
        success, message = twilio_verify_otp(phone_number, otp)
    else:
        success, message = verify_inapp_otp(phone_number, otp)

    if success:
        clear_rate_limit(phone_number)

    return success, message


def twilio_send_otp(phone_number, message_body=None):
    """
    Sends a One-Time Password (OTP) using Twilio to the specified phone number.

    Args:
        phone_number (str): The recipient's phone number in E.164 format (e.g., "+1234567890").
        message_body (str, optional): A custom message body for the OTP.

    Returns:
        tuple:
            - bool: True if the message was sent successfully, False otherwise.
            - str: A detailed message indicating the result.
    """
    client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

    try:
        if message_body:
            message = client.messages.create(
                body=message_body,
                from_=TWILIO_PHONE_NUMBER,
                to=phone_number,
            )
            status = message.status
        else:
            verification = client.verify.v2.services(
                TWILIO_SERVICE_SID
            ).verifications.create(to=phone_number, channel="sms")
            status = verification.status

        if status in ("accepted", "pending", "queued"):
            logger.info("OTP sent successfully.")
            return True, "OTP sent successfully. Please check your phone for the code."

        logger.error("Failed to send OTP. Twilio status: %s", status)
        return (
            False,
            "Failed to send OTP. Please ensure your phone number is correct and try again later.",
        )
    except TwilioRestException as e:
        logger.error("Twilio error while sending OTP: %s", e)
        return (False, "Failed to send OTP. Please try again later.")


def twilio_verify_otp(phone_number, otp):
    """
    Verify the provided OTP using Twilio for the given phone number.

    Args:
        phone_number (str): The phone number to verify the OTP for.
        otp (str): The OTP to verify.

    Returns:
        tuple: A tuple containing the following elements:
            - A boolean indicating whether the OTP was verified successfully.
            - A message indicating the result of the OTP verification process.
    """
    client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

    try:
        verification_check = client.verify.v2.services(
            TWILIO_SERVICE_SID
        ).verification_checks.create(to=phone_number, code=otp)

        status = verification_check.status

        if status == "approved":
            logger.info("OTP verified successfully.")
            return True, "OTP verified successfully."

        if status == "pending":
            logger.error("Incorrect OTP provided.")
            return False, "Incorrect OTP. Please double-check the code and try again."

        logger.warning("Unexpected OTP verification status: %s", status)
        return (False, "Failed to verify OTP. Please try again later.")
    except TwilioRestException as e:
        logger.error("Twilio error while verifying OTP: %s", e)

        if e.status == 400:
            return False, "Incorrect OTP. Please double-check the code and try again."

        if e.status == 404:
            return False, "OTP verification expired. Please request a new code."

        logger.warning("Unexpected OTP verification status: %s", e.status)
        return (False, "Failed to verify OTP. Please try again later.")


def mock_send_otp():
    """
    Mock function to send OTP to a phone number.

    Returns:
        tuple: A tuple containing two elements:
            - A boolean indicating whether the OTP was sent successfully.
            - A string message indicating the result of the OTP sending process.
    """
    logger.info("Mock OTP sent to phone number.")
    return True, "OTP sent successfully. Please check your phone for the code."


def mock_verify_otp(otp):
    """
    Mock function to verify OTP for a phone number.

    Args:
        otp (str): The OTP code to verify.

    Returns:
        tuple: A tuple containing two elements:
            - A boolean indicating whether the OTP was verified successfully.
            - A string message indicating the result of the OTP verification process.
    """
    if otp == "123456":
        logger.info("Mock OTP verified successfully.")
        return True, "OTP verified successfully."

    logger.warning("Incorrect OTP provided.")
    return False, "Incorrect OTP. Please double-check the code and try again."


def clean_rate_limit_store(phone_number):
    """
    Clean up expired rate limit records for the provided phone number.

    Args:
        phone_number (str): The phone number to clean up rate limit records for.
    """
    logger.debug("Cleaning up expired rate limit records for phone number...")
    current_time = datetime.datetime.now()

    rows_deleted = (
        OTPRateLimit.delete()
        .where(
            OTPRateLimit.phone_number == phone_number,
            OTPRateLimit.date_expires < current_time,
            OTPRateLimit.attempt_count >= RATE_LIMIT_WINDOWS[-1]["count"],
        )
        .execute()
    )

    if rows_deleted > 0:
        logger.info("Successfully cleaned up expired rate limit records.")


def increment_rate_limit(phone_number):
    """
    Increment the rate limit counter for the provided phone number.

    Args:
        phone_number (str): The phone number to increment the rate limit counter for.

    Returns:
        OTPRateLimit: The updated or created OTP rate limit record.
    """
    logger.debug("Incrementing rate limit for phone number...")
    current_time = datetime.datetime.now()

    rate_limit, created = OTPRateLimit.get_or_create(
        phone_number=phone_number,
        defaults={
            "date_expires": current_time
            + datetime.timedelta(minutes=RATE_LIMIT_WINDOWS[0]["duration"]),
            "attempt_count": RATE_LIMIT_WINDOWS[0]["count"],
        },
    )

    if not created:
        rate_limit.attempt_count += 1
        index = next(
            (
                i
                for i, window in enumerate(RATE_LIMIT_WINDOWS)
                if window["count"] == rate_limit.attempt_count
            ),
            -1,
        )

        rate_limit.date_expires = current_time + datetime.timedelta(
            minutes=RATE_LIMIT_WINDOWS[index]["duration"]
        )
        rate_limit.save()

    logger.info(
        "Rate limit incremented for phone number. Attempts: %d, Expires at: %s",
        rate_limit.attempt_count,
        rate_limit.date_expires,
    )

    return rate_limit


def clear_rate_limit(phone_number):
    """
    Clear the rate limit counter for the provided phone number.

    Args:
        phone_number (str): The phone number to clear the rate limit counter for.
    """
    logger.debug("Clearing rate limit for phone number...")
    OTPRateLimit.delete().where(OTPRateLimit.phone_number == phone_number).execute()

    logger.info("Rate limit cleared for phone number.")


def generate_otp(length=6):
    """
    Generate a random OTP of specified length.

    Args:
        length (int): The length of the OTP to generate.

    Returns:
        str: The generated OTP.
    """
    return str(random.randint(10 ** (length - 1), 10**length - 1))


def create_inapp_otp(phone_number, exp_time=1051200):
    """
    Create or update an OTP for the given phone number.

    Args:
        phone_number (str): The phone number for which the OTP will be generated.
        exp_time (int): The expiration time in minutes for the OTP. Defaults to 1051200 minutes.

    Returns:
        tuple:
            - str: A message describing the result of the OTP generation attempt.
            - tuple:
                - str: The OTP code.
                - int: The expiration time as a Unix timestamp (seconds since epoch).
    """
    otp_entry, created = OTP.get_or_create(
        phone_number=phone_number,
        is_verified=False,
        defaults={
            "otp_code": generate_otp(),
            "date_expires": datetime.datetime.now()
            + datetime.timedelta(minutes=exp_time),
            "attempt_count": 0,
        },
    )

    if not created:
        otp_entry.otp_code = generate_otp()
        otp_entry.date_expires = datetime.datetime.now() + datetime.timedelta(
            minutes=exp_time
        )
        otp_entry.attempt_count = 0
        otp_entry.is_verified = False
        otp_entry.save()

    expiration_time = int(otp_entry.date_expires.timestamp())
    return "OTP created successfully.", (otp_entry.otp_code, expiration_time)


def verify_inapp_otp(phone_number, otp_code):
    """
    Verify the OTP for a given phone number.

    Args:
        phone_number (str): The phone number for which the OTP was generated.
        otp_code (str): The OTP code entered for verification.

    Returns:
        tuple:
            - bool: Indicates whether the OTP verification was successful.
            - str: A message describing the result of the OTP verification attempt.
    """
    otp_entry = OTP.get_or_none(
        OTP.phone_number == phone_number,
        ~(OTP.is_verified),
    )

    if not otp_entry:
        verified_otp_entry = OTP.get_or_none(
            OTP.phone_number == phone_number,
            OTP.is_verified,
            OTP.otp_code == otp_code,
        )
        if verified_otp_entry:
            return True, "OTP is already verified for this phone number."
        return False, "No OTP record found for this phone number."

    if otp_entry.is_expired():
        return False, "The OTP has expired. Please request a new one."

    if otp_entry.otp_code != otp_code:
        otp_entry.increment_attempt_count()
        return False, "Incorrect OTP. Please try again."

    otp_entry.is_verified = True
    otp_entry.save()

    return True, "OTP verified successfully!"
