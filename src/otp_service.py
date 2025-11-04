# SPDX-License-Identifier: GPL-3.0-only
"""OTP Service Module - handles SMS and email OTP delivery."""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Tuple, Optional
import datetime
import random
import re
import requests

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

EMAIL_SERVICE_URL = get_configs("EMAIL_SERVICE_URL")
EMAIL_SERVICE_API_KEY = get_configs("EMAIL_SERVICE_API_KEY")
EMAIL_FROM_ADDRESS = get_configs(
    "EMAIL_FROM_ADDRESS", default_value="noreply@relaysms.com"
)
EMAIL_FROM_NAME = get_configs("EMAIL_FROM_NAME", default_value="RelaySMS")

MOCK_OTP = get_configs("MOCK_OTP")
MOCK_OTP = MOCK_OTP.lower() == "true" if MOCK_OTP is not None else False
DUMMY_PHONENUMBERS = get_configs(
    "DUMMY_PHONENUMBER", default_value="+237123456789"
).split(",")
DUMMY_EMAILS = get_configs("DUMMY_EMAIL", default_value="test@example.com").split(",")

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


class ContactType(Enum):
    """Contact types for OTP delivery."""

    PHONE = "phone_number"
    EMAIL = "email_address"


class MockOTPHandler:
    """Centralized mock OTP handling for testing."""

    MOCK_CODE = "123456"

    @staticmethod
    def send() -> Tuple[bool, str]:
        """Mock OTP send - always succeeds."""
        logger.info("Mock OTP sent")
        return True, "OTP sent successfully. Please check for the code."

    @staticmethod
    def verify(otp_code: str) -> Tuple[bool, str]:
        """Mock OTP verification."""
        if otp_code == MockOTPHandler.MOCK_CODE:
            logger.info("Mock OTP verified")
            return True, "OTP verified successfully."
        logger.warning("Incorrect mock OTP")
        return False, "Incorrect OTP. Please double-check the code and try again."


class OTPDeliveryMethod(ABC):
    """Base class for OTP delivery methods."""

    @abstractmethod
    def send(
        self, identifier: str, otp_code: str, message_body: Optional[str] = None
    ) -> Tuple[bool, str]:
        """Send OTP to identifier."""

    @abstractmethod
    def verify(self, identifier: str, otp_code: str) -> Tuple[bool, str]:
        """Verify OTP for identifier."""


class SMSDeliveryMethod(OTPDeliveryMethod):
    """SMS OTP delivery via Twilio and Queuedroid."""

    def send(
        self, identifier: str, otp_code: str, message_body: Optional[str] = None
    ) -> Tuple[bool, str]:
        """Send OTP via SMS."""
        logger.debug("Sending SMS OTP")

        if identifier in DUMMY_PHONENUMBERS:
            return MockOTPHandler.send()

        region_code = get_phonenumber_region_code(identifier)
        if region_code in QUEUEDROID_SUPPORTED_VERIFICATION_REGION_CODES:
            return self._send_with_queuedroid(identifier, otp_code)
        return self._send_with_twilio(identifier, message_body)

    def verify(self, identifier: str, otp_code: str) -> Tuple[bool, str]:
        """Verify OTP via SMS."""
        logger.debug("Verifying SMS OTP")

        if identifier in DUMMY_PHONENUMBERS:
            return MockOTPHandler.verify(otp_code)

        region_code = get_phonenumber_region_code(identifier)
        if region_code in QUEUEDROID_SUPPORTED_VERIFICATION_REGION_CODES:
            return verify_inapp_otp(identifier, otp_code, ContactType.PHONE)
        return self._verify_with_twilio(identifier, otp_code)

    def verify_with_twilio(self, identifier: str, otp_code: str) -> Tuple[bool, str]:
        """Public method for Twilio verification."""
        return self._verify_with_twilio(identifier, otp_code)

    def _send_with_queuedroid(
        self, phone_number: str, otp_code: str
    ) -> Tuple[bool, str]:
        """Send OTP via Queuedroid."""
        message_body = f"Your RelaySMS Verification Code is: {otp_code}"
        success = send_with_queuedroid(phone_number, message_body)
        message = (
            "OTP sent. Check your phone."
            if success
            else "Failed to send OTP. Try again."
        )
        return success, message

    def _send_with_twilio(
        self, phone_number: str, message_body: Optional[str] = None
    ) -> Tuple[bool, str]:
        """Send OTP via Twilio."""
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

    def _verify_with_twilio(self, phone_number: str, otp_code: str) -> Tuple[bool, str]:
        """Verify OTP via Twilio."""
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

        try:
            verification_check = client.verify.v2.services(
                TWILIO_SERVICE_SID
            ).verification_checks.create(to=phone_number, code=otp_code)

            if verification_check.status == "approved":
                logger.info("OTP verified via Twilio")
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
        self, identifier: str, otp_code: str, message_body: Optional[str] = None
    ) -> Tuple[bool, str]:
        """Send OTP via email."""
        logger.debug("Sending email OTP")

        if identifier in DUMMY_EMAILS:
            return MockOTPHandler.send()
        return self._send_with_email_service(identifier, otp_code, message_body)

    def verify(self, identifier: str, otp_code: str) -> Tuple[bool, str]:
        """Verify OTP via email."""
        logger.debug("Verifying email OTP")

        if identifier in DUMMY_EMAILS:
            return MockOTPHandler.verify(otp_code)
        return verify_inapp_otp(identifier, otp_code, ContactType.EMAIL)

    def _send_with_email_service(
        self, email_address: str, otp_code: str, message_body: Optional[str] = None
    ) -> Tuple[bool, str]:
        """Send OTP via HTTP email service."""
        if not EMAIL_SERVICE_URL or not EMAIL_SERVICE_API_KEY:
            logger.error("Email service not configured")
            return False, "Email service unavailable. Contact support."

        try:
            body = (
                message_body
                or f"""Hello,

Your RelaySMS verification code is: {otp_code}

This code expires in 10 minutes. Do not share this code.

If you didn't request this, please ignore this email.

Best regards,
The RelaySMS Team"""
            )

            payload = {
                "to": email_address,
                "from": EMAIL_FROM_ADDRESS,
                "from_name": EMAIL_FROM_NAME,
                "subject": "Your RelaySMS Verification Code",
                "body": body,
                "content_type": "text/plain",
            }

            headers = {
                "Authorization": f"Bearer {EMAIL_SERVICE_API_KEY}",
                "Content-Type": "application/json",
            }

            response = requests.post(
                EMAIL_SERVICE_URL, json=payload, headers=headers, timeout=30
            )

            if response.status_code == 200:
                logger.info("OTP sent via email")
                return True, "OTP sent. Check your email."

            logger.error(
                "Email service error %d: %s", response.status_code, response.text
            )
            return False, "Failed to send OTP via email. Try again."

        except requests.exceptions.RequestException as e:
            logger.error("Email service request error: %s", e)
            return False, "Failed to send OTP via email. Try again."


class OTPService:
    """Main OTP service handling phone and email delivery."""

    def __init__(self):
        self.sms_delivery = SMSDeliveryMethod()
        self.email_delivery = EmailDeliveryMethod()

    def validate_identifier(
        self, identifier: str, contact_type: ContactType
    ) -> Tuple[bool, str]:
        """Validate identifier format."""
        if contact_type == ContactType.EMAIL:
            email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
            if not re.match(email_pattern, identifier):
                return False, "Invalid email address format."
        elif contact_type == ContactType.PHONE:
            if (
                not identifier.startswith("+")
                or not identifier[1:].replace(" ", "").replace("-", "").isdigit()
            ):
                return (
                    False,
                    "Invalid phone number format. Use international format (e.g., +1234567890).",
                )
        return True, ""

    def check_region_restrictions(
        self, identifier: str, contact_type: ContactType
    ) -> Tuple[bool, str]:
        """Check region restrictions for phone numbers."""
        if contact_type == ContactType.PHONE and OTP_ALLOWED_COUNTRIES:
            region_code = get_phonenumber_region_code(identifier)
            if region_code not in OTP_ALLOWED_COUNTRIES:
                logger.info("OTP blocked for region: %s", region_code)
                return (
                    False,
                    "OTP service unavailable for your region. Contact support.",
                )
        return True, ""


def get_rate_limit_key(identifier: str, contact_type: ContactType) -> dict:
    """Get rate limiting field based on contact type."""
    return (
        {"email": identifier}
        if contact_type == ContactType.EMAIL
        else {"phone_number": identifier}
    )


def is_rate_limited(identifier: str, contact_type: ContactType) -> bool:
    """Check if identifier has exceeded OTP rate limit."""
    logger.debug("Checking rate limit")

    current_time = datetime.datetime.now()
    rate_limit_filter = get_rate_limit_key(identifier, contact_type)
    rate_limit = OTPRateLimit.get_or_none(**rate_limit_filter)

    if rate_limit:
        clean_rate_limit_store(identifier, contact_type)
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
                "Rate limit exceeded: %d min window",
                RATE_LIMIT_WINDOWS[index]["duration"],
            )
            return True
    return False


def send_otp(
    identifier: str,
    contact_type: ContactType = ContactType.PHONE,
    message_body: Optional[str] = None,
) -> Tuple[bool, str, Optional[int]]:
    """Send OTP to identifier (phone or email)."""
    logger.debug("Sending OTP")

    if not OTP_ENABLED:
        logger.info("OTP service disabled")
        return False, "OTP service temporarily unavailable. Contact support.", None

    service = OTPService()

    is_valid, validation_message = service.validate_identifier(identifier, contact_type)
    if not is_valid:
        return False, validation_message, None

    is_allowed, restriction_message = service.check_region_restrictions(
        identifier, contact_type
    )
    if not is_allowed:
        return False, restriction_message, None

    if is_rate_limited(identifier, contact_type):
        return False, "Too many OTP requests. Wait and try again.", None

    expires = None

    if MOCK_OTP:
        success, message = MockOTPHandler.send()
    else:
        _, otp_result = create_inapp_otp(identifier, contact_type)
        otp_code, _ = otp_result

        if contact_type == ContactType.EMAIL:
            success, message = service.email_delivery.send(
                identifier, otp_code, message_body
            )
        else:
            success, message = service.sms_delivery.send(
                identifier, otp_code, message_body
            )

    if success:
        otp_record = increment_rate_limit(identifier, contact_type)
        expires = int(otp_record.date_expires.timestamp())

    return success, message, expires


def verify_otp(
    identifier: str,
    otp_code: str,
    contact_type: ContactType = ContactType.PHONE,
    use_twilio: bool = True,
) -> Tuple[bool, str]:
    """Verify OTP for identifier."""
    logger.debug("Verifying OTP")

    if not OTP_ENABLED:
        logger.info("OTP service disabled")
        return False, "OTP service temporarily unavailable. Contact support."

    service = OTPService()

    rate_limit_filter = get_rate_limit_key(identifier, contact_type)
    if not OTPRateLimit.get_or_none(**rate_limit_filter):
        return False, "OTP not initiated. Request a new OTP first."

    if contact_type == ContactType.PHONE:
        is_allowed, restriction_message = service.check_region_restrictions(
            identifier, contact_type
        )
        if not is_allowed:
            return False, restriction_message

    if MOCK_OTP:
        success, message = MockOTPHandler.verify(otp_code)
    else:
        if contact_type == ContactType.EMAIL:
            success, message = service.email_delivery.verify(identifier, otp_code)
        else:
            if use_twilio and identifier not in DUMMY_PHONENUMBERS:
                region_code = get_phonenumber_region_code(identifier)
                if region_code not in QUEUEDROID_SUPPORTED_VERIFICATION_REGION_CODES:
                    success, message = service.sms_delivery.verify_with_twilio(
                        identifier, otp_code
                    )
                else:
                    success, message = verify_inapp_otp(
                        identifier, otp_code, ContactType.PHONE
                    )
            else:
                success, message = service.sms_delivery.verify(identifier, otp_code)

    if success:
        clear_rate_limit(identifier, contact_type)

    return success, message


def clean_rate_limit_store(identifier: str, contact_type: ContactType):
    """Clean expired rate limit records."""
    logger.debug("Cleaning expired rate limits")

    current_time = datetime.datetime.now()
    rate_limit_filter = get_rate_limit_key(identifier, contact_type)

    rows_deleted = (
        OTPRateLimit.delete()
        .where(
            *[
                getattr(OTPRateLimit, field) == value
                for field, value in rate_limit_filter.items()
            ],
            OTPRateLimit.date_expires < current_time,
            OTPRateLimit.attempt_count >= RATE_LIMIT_WINDOWS[-1]["count"],
        )
        .execute()
    )

    if rows_deleted > 0:
        logger.info("Cleaned %d expired rate limit records", rows_deleted)


def increment_rate_limit(identifier: str, contact_type: ContactType):
    """Increment rate limit counter for identifier."""
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

    contact_type_str = "email" if contact_type == ContactType.EMAIL else "phone"
    logger.info(
        "Rate limit: %s attempts=%d expires=%s",
        contact_type_str,
        rate_limit.attempt_count,
        rate_limit.date_expires,
    )

    return rate_limit


def clear_rate_limit(identifier: str, contact_type: ContactType):
    """Clear rate limit counter for identifier."""
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
    """Generate random OTP of specified length."""
    return str(random.randint(10 ** (length - 1), 10**length - 1))


def create_inapp_otp(
    identifier: str, contact_type: ContactType, exp_time: int = 10
) -> Tuple[str, Tuple[str, int]]:
    """Create or update OTP for identifier."""
    otp_filter = {}
    if contact_type == ContactType.EMAIL:
        otp_filter["email"] = identifier
    else:
        otp_filter["phone_number"] = identifier
    otp_filter["is_verified"] = False

    otp_entry, created = OTP.get_or_create(
        **otp_filter,
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


def verify_inapp_otp(
    identifier: str, otp_code: str, contact_type: ContactType
) -> Tuple[bool, str]:
    """Verify in-app generated OTP."""
    otp_filter = {}
    if contact_type == ContactType.EMAIL:
        otp_filter["email"] = identifier
    else:
        otp_filter["phone_number"] = identifier

    otp_entry = OTP.get_or_none(
        *[getattr(OTP, field) == value for field, value in otp_filter.items()],
        ~(OTP.is_verified),
    )

    if not otp_entry:
        verified_otp_entry = OTP.get_or_none(
            *[getattr(OTP, field) == value for field, value in otp_filter.items()],
            OTP.is_verified,
            OTP.otp_code == otp_code,
        )
        if verified_otp_entry:
            contact_type_str = (
                "email" if contact_type == ContactType.EMAIL else "phone number"
            )
            return True, f"OTP already verified for this {contact_type_str}."

        contact_type_str = (
            "email" if contact_type == ContactType.EMAIL else "phone number"
        )
        return False, f"No OTP record found for this {contact_type_str}."

    if otp_entry.is_expired():
        return False, "OTP expired. Request a new one."

    if otp_entry.otp_code != otp_code:
        otp_entry.increment_attempt_count()
        return False, "Incorrect OTP. Try again."

    otp_entry.is_verified = True
    otp_entry.save()
    return True, "OTP verified successfully!"
