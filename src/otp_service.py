# SPDX-License-Identifier: GPL-3.0-only
"""OTP Service Module - handles SMS and email OTP delivery."""

import datetime
import secrets
import string
from abc import ABC, abstractmethod
from typing import Optional, Tuple

import requests
from twilio.base.exceptions import TwilioRestException
from twilio.rest import Client

from base_logger import get_logger
from src.db_models import OTP, OTPRateLimit
from src.sms_outbound import (
    QUEUEDROID_SUPPORTED_VERIFICATION_REGION_CODES,
    get_phonenumber_region_code,
    send_with_queuedroid,
)
from src.types import ContactType, OTPAction
from src.utils import get_bool_config, get_configs, get_list_config

logger = get_logger(__name__)

TWILIO_ACCOUNT_SID = get_configs("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = get_configs("TWILIO_AUTH_TOKEN")
TWILIO_SERVICE_SID = get_configs("TWILIO_SERVICE_SID")
TWILIO_PHONE_NUMBER = get_configs("TWILIO_PHONE_NUMBER")

MOCK_OTP = get_bool_config("MOCK_OTP")
DUMMY_PHONENUMBERS = get_configs(
    "DUMMY_PHONENUMBER", default_value="+237123456789"
).split(",")

SMS_OTP_ENABLED = get_bool_config("SMS_OTP_ENABLED")
SMS_OTP_ALLOWED_COUNTRIES = get_list_config("SMS_OTP_ALLOWED_COUNTRIES")
SMS_OTP_AUTH_ENABLED = get_bool_config("SMS_OTP_AUTH_ENABLED")
SMS_OTP_SIGNUP_ENABLED = get_bool_config("SMS_OTP_SIGNUP_ENABLED")
SMS_OTP_RESET_PASSWORD_ENABLED = get_bool_config("SMS_OTP_RESET_PASSWORD_ENABLED")

EMAIL_OTP_ENABLED = get_bool_config("EMAIL_OTP_ENABLED")
EMAIL_OTP_AUTH_ENABLED = get_bool_config("EMAIL_OTP_AUTH_ENABLED")
EMAIL_OTP_SIGNUP_ENABLED = get_bool_config("EMAIL_OTP_SIGNUP_ENABLED")
EMAIL_OTP_RESET_PASSWORD_ENABLED = get_bool_config("EMAIL_OTP_RESET_PASSWORD_ENABLED")

EMAIL_SERVICE_URL = get_configs("EMAIL_SERVICE_URL")
EMAIL_SERVICE_API_KEY = get_configs("EMAIL_SERVICE_API_KEY")
EMAIL_VERIFICATION_SENDER_ADDRESS = get_configs("EMAIL_VERIFICATION_SENDER_ADDRESS")

EMAIL_LOGO_URL = get_configs("EMAIL_LOGO_URL")
EMAIL_SUBJECT = get_configs(
    "EMAIL_SUBJECT", default_value="{{ project_name }} Verification Code"
)
EMAIL_ORGANIZATION_NAME = get_configs(
    "EMAIL_ORGANIZATION_NAME", default_value="SMSWithoutBorders"
)
EMAIL_WEBSITE_URL = get_configs(
    "EMAIL_WEBSITE_URL", default_value="https://relay.smswithoutborders.com"
)
EMAIL_PROJECT_NAME = get_configs("EMAIL_PROJECT_NAME", default_value="RelaySMS")
EMAIL_ABUSE_EMAIL = get_configs(
    "EMAIL_ABUSE_EMAIL", default_value="abuse@smswithoutborders.com"
)
EMAIL_SUPPORT_EMAIL = get_configs(
    "EMAIL_SUPPORT_EMAIL", default_value="support@smswithoutborders.com"
)
EMAIL_OTP_EXPIRY_MINUTES = int(
    get_configs("EMAIL_OTP_EXPIRY_MINUTES", default_value="10")
)

MAX_OTP_REQUESTS = int(get_configs("OTP_MAX_REQUESTS", default_value="5"))
MAX_OTP_VERIFY_ATTEMPTS = int(get_configs("OTP_MAX_VERIFY_ATTEMPTS", default_value="5"))

RATE_LIMIT_WINDOWS = [
    {
        "duration": int(
            get_configs("OTP_RATE_LIMIT_WINDOW_1_DURATION", default_value="5")
        ),
        "count": int(get_configs("OTP_RATE_LIMIT_WINDOW_1_COUNT", default_value="1")),
    },
    {
        "duration": int(
            get_configs("OTP_RATE_LIMIT_WINDOW_2_DURATION", default_value="10")
        ),
        "count": int(get_configs("OTP_RATE_LIMIT_WINDOW_2_COUNT", default_value="2")),
    },
    {
        "duration": int(
            get_configs("OTP_RATE_LIMIT_WINDOW_3_DURATION", default_value="30")
        ),
        "count": int(get_configs("OTP_RATE_LIMIT_WINDOW_3_COUNT", default_value="3")),
    },
    {
        "duration": int(
            get_configs("OTP_RATE_LIMIT_WINDOW_4_DURATION", default_value="120")
        ),
        "count": int(get_configs("OTP_RATE_LIMIT_WINDOW_4_COUNT", default_value="4")),
    },
    {
        "duration": int(
            get_configs("OTP_RATE_LIMIT_WINDOW_5_DURATION", default_value="1440")
        ),
        "count": int(get_configs("OTP_RATE_LIMIT_WINDOW_5_COUNT", default_value="5")),
    },
]


class MockOTPHandler:
    """Mock OTP handler for testing."""

    MOCK_CODE = "123456"

    @staticmethod
    def send() -> Tuple[bool, str]:
        """Send mock OTP."""
        logger.info("Mock OTP sent")
        return True, "OTP sent successfully. Please check for the code."

    @staticmethod
    def verify(otp_code: str) -> Tuple[bool, str]:
        """Verify mock OTP."""
        if otp_code == MockOTPHandler.MOCK_CODE:
            logger.info("Mock OTP verified")
            return True, "OTP verified successfully."
        logger.warning("Incorrect mock OTP")
        return False, "Incorrect OTP. Please double-check the code and try again."


class OTPDeliveryMethod(ABC):
    """Base class for OTP delivery methods."""

    @abstractmethod
    def send(
        self, identifier: str, action: OTPAction, message_body: Optional[str] = None
    ) -> Tuple[bool, str]:
        """Send OTP."""

    @abstractmethod
    def verify(
        self, identifier: str, otp_code: str, action: OTPAction
    ) -> Tuple[bool, str]:
        """Verify OTP."""


class SMSDeliveryMethod(OTPDeliveryMethod):
    """SMS OTP delivery via Twilio and Queuedroid."""

    def send(
        self, identifier: str, action: OTPAction, message_body: Optional[str] = None
    ) -> Tuple[bool, str]:
        """Send OTP via SMS."""
        logger.debug("Sending SMS OTP for action: %s", action.value)

        if SMS_OTP_ALLOWED_COUNTRIES:
            region_code, country_name = get_phonenumber_region_code(identifier)
            if region_code not in SMS_OTP_ALLOWED_COUNTRIES:
                logger.info(
                    "SMS OTP blocked for country: %s with region: %s",
                    country_name,
                    region_code,
                )
                return (
                    False,
                    "SMS OTP service unavailable for your region. Try email OTP or contact support.",
                )

        if MOCK_OTP or identifier in DUMMY_PHONENUMBERS:
            return MockOTPHandler.send()

        region_code, _ = get_phonenumber_region_code(identifier)
        if region_code in QUEUEDROID_SUPPORTED_VERIFICATION_REGION_CODES:
            _, otp_result = create_inapp_otp(identifier, action, ContactType.PHONE)
            otp_code, _ = otp_result
            return self._send_with_queuedroid(identifier, otp_code)
        return self._send_with_twilio(identifier, action, message_body)

    def verify(
        self, identifier: str, otp_code: str, action: OTPAction
    ) -> Tuple[bool, str]:
        """Verify OTP via SMS."""
        logger.debug("Verifying SMS OTP for action: %s", action.value)

        if SMS_OTP_ALLOWED_COUNTRIES:
            region_code, country_name = get_phonenumber_region_code(identifier)
            if region_code not in SMS_OTP_ALLOWED_COUNTRIES:
                logger.info(
                    "SMS OTP blocked for country: %s with region: %s",
                    country_name,
                    region_code,
                )
                return (
                    False,
                    "SMS OTP service unavailable for your region. Try email OTP or contact support.",
                )

        if MOCK_OTP or identifier in DUMMY_PHONENUMBERS:
            return MockOTPHandler.verify(otp_code)

        region_code, _ = get_phonenumber_region_code(identifier)
        if region_code in QUEUEDROID_SUPPORTED_VERIFICATION_REGION_CODES:
            return verify_inapp_otp(identifier, otp_code, action, ContactType.PHONE)
        return self._verify_with_twilio(identifier, otp_code, action)

    def _send_with_queuedroid(
        self, phone_number: str, otp_code: str
    ) -> Tuple[bool, str]:
        """Send OTP via Queuedroid."""
        message_body = f"Your RelaySMS Verification Code is: {otp_code}"
        success = send_with_queuedroid(phone_number, message_body)
        return (
            (True, "OTP sent. Check your phone.")
            if success
            else (False, "Failed to send OTP. Try again.")
        )

    def _send_with_twilio(
        self, phone_number: str, action: OTPAction, message_body: Optional[str] = None
    ) -> Tuple[bool, str]:
        """Send OTP via Twilio."""
        otp_data = {
            "phone_number": phone_number,
            "date_expires": datetime.datetime.now() + datetime.timedelta(minutes=10),
            "attempt_count": 0,
            "purpose": action.value,
            "otp_code": None,
        }

        OTP.replace(**otp_data).execute()
        logger.info("Twilio OTP record created for action: %s", action.value)

        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

        try:
            if message_body:
                message = client.messages.create(
                    body=message_body, from_=TWILIO_PHONE_NUMBER, to=phone_number
                )
                status = message.status
            else:
                verification = client.verify.v2.services(
                    TWILIO_SERVICE_SID
                ).verifications.create(to=phone_number, channel="sms")
                status = verification.status

            if status in ("accepted", "pending", "queued"):
                logger.info("OTP sent via Twilio")
                return True, "OTP sent. Check your phone."

            logger.error("Twilio send failed: %s", status)
            return False, "Failed to send OTP. Check your number and try again."

        except TwilioRestException as e:
            logger.error("Twilio error: %s", e)
            return False, "Failed to send OTP. Try again."

    def _verify_with_twilio(
        self, phone_number: str, otp_code: str, action: OTPAction
    ) -> Tuple[bool, str]:
        """Verify OTP via Twilio."""
        otp_entry = OTP.get_or_none(OTP.phone_number == phone_number)

        if not otp_entry:
            logger.warning("No Twilio OTP record found for verification")
            return False, "OTP record not found. Request a new OTP."

        if otp_entry.purpose != action.value:
            logger.warning(
                "Twilio OTP action mismatch: expected '%s', got '%s'",
                otp_entry.purpose,
                action.value,
            )
            return False, "OTP action mismatch. Request a new OTP."

        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

        try:
            verification_check = client.verify.v2.services(
                TWILIO_SERVICE_SID
            ).verification_checks.create(to=phone_number, code=otp_code)

            if verification_check.status == "approved":
                logger.info("OTP verified via Twilio")

                OTP.delete().where(OTP.phone_number == phone_number).execute()
                logger.info("Twilio OTP record deleted")

                return True, "OTP verified successfully."

            if verification_check.status == "pending":
                logger.error("Incorrect OTP")
                return False, "Incorrect OTP. Double-check and try again."

            logger.warning(
                "Unexpected verification status: %s", verification_check.status
            )
            return False, "Failed to verify OTP. Try again."

        except TwilioRestException as e:
            logger.error("Twilio verify error: %s", e)

            if e.status == 400:
                return False, "Incorrect OTP. Double-check and try again."
            if e.status == 404:
                return False, "OTP expired. Request a new code."

            return False, "Failed to verify OTP. Try again."


class EmailDeliveryMethod(OTPDeliveryMethod):
    """Email OTP delivery via HTTP email service."""

    def send(
        self, identifier: str, action: OTPAction, message_body: Optional[str] = None
    ) -> Tuple[bool, str]:
        """Send OTP via email."""
        logger.debug("Sending email OTP for action: %s", action.value)

        if MOCK_OTP:
            return MockOTPHandler.send()

        _, otp_result = create_inapp_otp(
            identifier, action, ContactType.EMAIL, EMAIL_OTP_EXPIRY_MINUTES
        )
        otp_code, _ = otp_result

        return self._send_with_email_service(identifier, otp_code, message_body)

    def verify(
        self, identifier: str, otp_code: str, action: OTPAction
    ) -> Tuple[bool, str]:
        """Verify OTP via email."""
        logger.debug(
            "Verifying email OTP for action: %s",
            action.value if action else "unspecified",
        )

        if MOCK_OTP:
            return MockOTPHandler.verify(otp_code)
        return verify_inapp_otp(identifier, otp_code, action, ContactType.EMAIL)

    def _send_with_email_service(
        self, email_address: str, otp_code: str, message_body: Optional[str] = None
    ) -> Tuple[bool, str]:
        """Send OTP via HTTP email service."""
        if not EMAIL_SERVICE_URL or not EMAIL_SERVICE_API_KEY:
            logger.error("Email service not configured")
            return False, "Email service unavailable. Contact support."

        try:
            expiration_time = datetime.datetime.now() + datetime.timedelta(
                minutes=EMAIL_OTP_EXPIRY_MINUTES
            )

            if expiration_time.tzinfo is None:
                expiration_time = expiration_time.replace(tzinfo=datetime.timezone.utc)

            expiration_date_time = expiration_time.strftime("%B %d, %Y at %I:%M %p %Z")
            expiration_time_words = f"{EMAIL_OTP_EXPIRY_MINUTES} minute{'s' if EMAIL_OTP_EXPIRY_MINUTES != 1 else ''}"

            payload = {
                "from_email": EMAIL_VERIFICATION_SENDER_ADDRESS,
                "to_email": email_address,
                "subject": EMAIL_SUBJECT,
                "template": "otp",
                "substitutions": {
                    "organization_name": EMAIL_ORGANIZATION_NAME,
                    "website_url": EMAIL_WEBSITE_URL,
                    "logo_url": EMAIL_LOGO_URL,
                    "project_name": EMAIL_PROJECT_NAME,
                    "expiration_time": expiration_time_words,
                    "otp_code": otp_code,
                    "expiration_date_time": expiration_date_time,
                    "abuse_email": EMAIL_ABUSE_EMAIL,
                    "support_email": EMAIL_SUPPORT_EMAIL,
                },
            }

            headers = {
                "Authorization": f"Bearer {EMAIL_SERVICE_API_KEY}",
                "Content-Type": "application/json",
            }

            response = requests.post(
                EMAIL_SERVICE_URL, json=payload, headers=headers, timeout=30
            )
            response.raise_for_status()
            response_data = response.json()

            if response.status_code == 200:
                if response_data.get("success"):
                    logger.info(
                        "OTP sent via email: %s", response_data.get("message", "")
                    )
                    return True, "OTP sent. Check your email."

                logger.error(
                    "Email service returned error: %s",
                    response_data.get("message", ""),
                )
                return False, "Failed to send OTP via email. Try again."

            logger.error(
                "Email service error %d: %s", response.status_code, response.text
            )
            return False, "Failed to send OTP via email. Try again."

        except requests.exceptions.RequestException as e:
            logger.error("Email service request error: %s", e)
            return False, "Failed to send OTP via email. Try again."


class OTPService:
    """OTP service for phone and email delivery."""

    def __init__(self):
        self.sms_delivery = SMSDeliveryMethod()
        self.email_delivery = EmailDeliveryMethod()


def is_delivery_method_enabled(
    contact_type: ContactType, action: Optional[OTPAction] = None
) -> bool:
    """Check if delivery method is enabled for action."""
    if contact_type == ContactType.EMAIL:
        if not EMAIL_OTP_ENABLED:
            return False
        if action == OTPAction.AUTH:
            return EMAIL_OTP_AUTH_ENABLED
        if action == OTPAction.SIGNUP:
            return EMAIL_OTP_SIGNUP_ENABLED
        if action == OTPAction.RESET_PASSWORD:
            return EMAIL_OTP_RESET_PASSWORD_ENABLED
        return EMAIL_OTP_ENABLED
    else:
        if not SMS_OTP_ENABLED:
            return False
        if action == OTPAction.AUTH:
            return SMS_OTP_AUTH_ENABLED
        if action == OTPAction.SIGNUP:
            return SMS_OTP_SIGNUP_ENABLED
        if action == OTPAction.RESET_PASSWORD:
            return SMS_OTP_RESET_PASSWORD_ENABLED
        return SMS_OTP_ENABLED


def get_rate_limit_key(identifier: str, contact_type: ContactType) -> dict:
    """Get rate limit filter key."""
    return (
        {"email": identifier}
        if contact_type == ContactType.EMAIL
        else {"phone_number": identifier}
    )


def is_rate_limited(identifier: str, contact_type: ContactType) -> bool:
    """Check if identifier is rate limited."""
    logger.debug("Checking rate limit")

    rate_limit_filter = get_rate_limit_key(identifier, contact_type)
    rate_limit = OTPRateLimit.get_or_none(**rate_limit_filter)

    if not rate_limit:
        return False

    if rate_limit.date_expires < datetime.datetime.now():
        logger.info("Rate limit expired, allowing request")
        return False

    logger.info(
        "Rate limit active: %d attempts, expires at %s",
        rate_limit.attempt_count,
        rate_limit.date_expires,
    )
    return True


def send_otp(
    identifier: str,
    action: OTPAction,
    contact_type: ContactType = ContactType.PHONE,
    message_body: Optional[str] = None,
) -> Tuple[bool, str, Optional[int]]:
    """Send OTP."""
    logger.debug("Sending OTP")

    if not is_delivery_method_enabled(contact_type, action):
        action_str = f" for {action.value}" if action else ""
        method_str = "email" if contact_type == ContactType.EMAIL else "SMS"
        logger.info("%s OTP disabled%s", method_str, action_str)
        return (
            False,
            f"{method_str.upper()} OTP service unavailable for your region. Contact support.",
            None,
        )

    if is_rate_limited(identifier, contact_type):
        return False, "Too many OTP requests. Wait and try again.", None

    otp_record = increment_rate_limit(identifier, contact_type)
    expires = int(otp_record.date_expires.timestamp())

    service = OTPService()

    if contact_type == ContactType.EMAIL:
        success, message = service.email_delivery.send(identifier, action, message_body)
    else:
        success, message = service.sms_delivery.send(identifier, action, message_body)

    return success, message, expires


def verify_otp(
    identifier: str,
    otp_code: str,
    action: OTPAction,
    contact_type: ContactType = ContactType.PHONE,
) -> Tuple[bool, str]:
    """Verify OTP."""
    logger.debug("Verifying OTP")

    if not is_delivery_method_enabled(contact_type, action):
        action_str = f" for {action.value}" if action else ""
        method_str = "email" if contact_type == ContactType.EMAIL else "SMS"
        logger.info("%s OTP disabled%s", method_str, action_str)
        return (
            False,
            f"{method_str.upper()} OTP service unavailable for your region. Contact support.",
        )

    rate_limit_filter = get_rate_limit_key(identifier, contact_type)
    if not OTPRateLimit.get_or_none(**rate_limit_filter):
        return False, "OTP not initiated. Request a new OTP first."

    service = OTPService()

    if contact_type == ContactType.EMAIL:
        success, message = service.email_delivery.verify(identifier, otp_code, action)
    else:
        success, message = service.sms_delivery.verify(identifier, otp_code, action)

    if success:
        clear_rate_limit(identifier, contact_type)

    return success, message


def increment_rate_limit(identifier: str, contact_type: ContactType):
    """Increment rate limit with progressive windows.

    Progressive windows increase duration after each attempt.
    """
    logger.debug("Incrementing rate limit")

    current_time = datetime.datetime.now()
    rate_limit_filter = get_rate_limit_key(identifier, contact_type)

    rate_limit, created = OTPRateLimit.get_or_create(
        **rate_limit_filter,
        defaults={
            "date_expires": current_time
            + datetime.timedelta(minutes=RATE_LIMIT_WINDOWS[0]["duration"]),
            "attempt_count": RATE_LIMIT_WINDOWS[0]["count"],
        },
    )

    if created:
        contact_type_str = "email" if contact_type == ContactType.EMAIL else "phone"
        logger.info(
            "Rate limit: %s attempts=%d expires=%s",
            contact_type_str,
            rate_limit.attempt_count,
            rate_limit.date_expires,
        )
        return rate_limit

    rate_limit = OTPRateLimit.get(**rate_limit_filter)

    if rate_limit.date_expires < current_time:
        if rate_limit.attempt_count >= MAX_OTP_REQUESTS:
            logger.info("Resetting rate limit after hard limit expiry")
            new_attempt_count = 1
        else:
            new_attempt_count = rate_limit.attempt_count + 1
    else:
        logger.warning(
            "increment_rate_limit called while rate limit active - this is unexpected"
        )
        new_attempt_count = rate_limit.attempt_count + 1

    if new_attempt_count > MAX_OTP_REQUESTS:
        new_attempt_count = MAX_OTP_REQUESTS

    index = next(
        (
            i
            for i, window in enumerate(RATE_LIMIT_WINDOWS)
            if window["count"] == new_attempt_count
        ),
        len(RATE_LIMIT_WINDOWS) - 1,
    )

    new_expires = current_time + datetime.timedelta(
        minutes=RATE_LIMIT_WINDOWS[index]["duration"]
    )

    rows_updated = (
        OTPRateLimit.update(attempt_count=new_attempt_count, date_expires=new_expires)
        .where(
            *[
                getattr(OTPRateLimit, field) == value
                for field, value in rate_limit_filter.items()
            ]
        )
        .execute()
    )

    if rows_updated == 0:
        logger.error("Failed to update rate limit - record may have been deleted")
        raise Exception("Rate limit update failed")

    rate_limit = OTPRateLimit.get(**rate_limit_filter)

    contact_type_str = "email" if contact_type == ContactType.EMAIL else "phone"
    logger.info(
        "Rate limit: %s attempts=%d expires=%s",
        contact_type_str,
        rate_limit.attempt_count,
        rate_limit.date_expires,
    )

    return rate_limit


def clear_rate_limit(identifier: str, contact_type: ContactType):
    """Clear rate limit."""
    logger.debug("Clearing rate limit")

    rate_limit_filter = get_rate_limit_key(identifier, contact_type)
    OTPRateLimit.delete().where(
        *[
            getattr(OTPRateLimit, field) == value
            for field, value in rate_limit_filter.items()
        ]
    ).execute()

    contact_type_str = "email" if contact_type == ContactType.EMAIL else "phone"
    logger.info("Rate limit cleared for %s", contact_type_str)


def generate_otp(length: int = 6) -> str:
    """Generate random numeric OTP."""
    return "".join(secrets.choice(string.digits) for _ in range(length))


def create_inapp_otp(
    identifier: str,
    action: OTPAction,
    contact_type: ContactType = ContactType.PHONE,
    exp_time: int = 10,
) -> Tuple[str, Tuple[str, int]]:
    """Create and store OTP."""
    otp_data = {
        "otp_code": generate_otp(),
        "date_expires": datetime.datetime.now() + datetime.timedelta(minutes=exp_time),
        "attempt_count": 0,
        "purpose": action.value,
    }

    if contact_type == ContactType.EMAIL:
        otp_data["email"] = identifier
        otp_data["phone_number"] = None
    else:
        otp_data["phone_number"] = identifier
        otp_data["email"] = None

    OTP.replace(**otp_data).execute()

    otp_filter = (
        {"email": identifier}
        if contact_type == ContactType.EMAIL
        else {"phone_number": identifier}
    )

    otp_entry = OTP.get(**otp_filter)
    expiration_time = int(otp_entry.date_expires.timestamp())
    return "OTP created successfully.", (otp_entry.otp_code, expiration_time)


def verify_inapp_otp(
    identifier: str, otp_code: str, action: OTPAction, contact_type: ContactType
) -> Tuple[bool, str]:
    """Verify OTP."""
    otp_filter = (
        {"email": identifier}
        if contact_type == ContactType.EMAIL
        else {"phone_number": identifier}
    )

    otp_entry = OTP.get_or_none(
        *[getattr(OTP, field) == value for field, value in otp_filter.items()]
    )

    if otp_entry and otp_entry.purpose != action.value:
        logger.warning(
            "OTP action mismatch: expected '%s', got '%s'",
            otp_entry.purpose,
            action.value,
        )
        return False, "OTP action mismatch. Request a new OTP."

    if not otp_entry:
        contact_type_str = (
            "email" if contact_type == ContactType.EMAIL else "phone number"
        )
        return False, f"No OTP record found for this {contact_type_str}."

    if otp_entry.is_expired():
        otp_entry.delete_instance()
        return False, "OTP expired. Request a new one."

    otp_entry.increment_attempt_count()

    if otp_entry.attempt_count >= MAX_OTP_VERIFY_ATTEMPTS:
        otp_entry.delete_instance()
        return False, "Too many incorrect attempts. OTP invalidated. Request a new one."

    if otp_entry.otp_code != otp_code:
        return False, "Incorrect OTP. Try again."

    otp_entry.delete_instance()
    return True, "OTP verified successfully!"
