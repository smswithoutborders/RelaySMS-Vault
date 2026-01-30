# SPDX-License-Identifier: GPL-3.0-only
"""OTP Service Module."""

import datetime
import secrets
import string
from abc import ABC, abstractmethod
from typing import Dict, Optional, Tuple

import phonenumbers
import requests
from phonenumbers import geocoder
from twilio.base.exceptions import TwilioRestException
from twilio.rest import Client as TwilioClient

from base_logger import get_logger
from src.db_models import OTP, OTPRateLimit
from src.types import ContactType, OTPAction
from src.utils import (
    get_bool_config,
    get_configs,
    get_list_config,
    hash_data,
    verify_hash,
)

logger = get_logger(__name__)

MOCK_OTP = get_bool_config("MOCK_OTP")
MAX_OTP_REQUESTS = int(get_configs("OTP_MAX_REQUESTS", default_value="5"))
MAX_OTP_VERIFY_ATTEMPTS = int(get_configs("OTP_MAX_VERIFY_ATTEMPTS", default_value="5"))

TWILIO_ACCOUNT_SID = get_configs("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = get_configs("TWILIO_AUTH_TOKEN")
TWILIO_SERVICE_SID = get_configs("TWILIO_SERVICE_SID")
TWILIO_PHONE_NUMBER = get_configs("TWILIO_PHONE_NUMBER")

QUEUEDROID_API_URL = get_configs(
    "QUEUEDROID_API_URL", default_value="https://api.queuedroid.com/v1/messages/send"
)
QUEUEDROID_API_KEY = get_configs("QUEUEDROID_API_KEY")
QUEUEDROID_EXCHANGE_ID = get_configs("QUEUEDROID_EXCHANGE_ID")
QUEUEDROID_QUEUE_ID = get_configs("QUEUEDROID_QUEUE_ID")
QUEUEDROID_SUPPORTED_VERIFICATION_REGION_CODES = get_list_config(
    "QUEUEDROID_SUPPORTED_VERIFICATION_REGION_CODES"
)


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


class OTPService:
    """Class for handling OTP operations."""

    def __init__(self, contact_type: ContactType, action: OTPAction) -> None:
        self.contact_type = contact_type
        self.action = action
        self.now = datetime.datetime.now()

    def __generate_otp(self, length: int = 6) -> str:
        """Generate a random OTP."""

        digits = string.digits
        otp = "".join(secrets.choice(digits) for _ in range(length))
        return otp

    def __is_rate_limited(self, contact: str) -> bool:
        """Check if OTP requests are rate limited for the contact."""

        rate_limit_record = OTPRateLimit.get_or_none(OTPRateLimit.identifier == contact)
        if not rate_limit_record:
            return False

        if rate_limit_record.expires_at < self.now:
            return False

        return True

    def __increment_rate_limit(self, contact: str) -> datetime.datetime:
        """Create or increment rate limit with progressive windows."""

        rate_limit = OTPRateLimit.get_or_none(OTPRateLimit.identifier == contact)

        if not rate_limit:
            expires_at = self.now + datetime.timedelta(
                minutes=RATE_LIMIT_WINDOWS[0]["duration"]
            )
            OTPRateLimit.create(
                identifier=contact,
                attempt_count=RATE_LIMIT_WINDOWS[0]["count"],
                expires_at=expires_at,
            )
            return expires_at

        if rate_limit.attempt_count >= MAX_OTP_REQUESTS:
            new_attempt_count = 1
        else:
            new_attempt_count = rate_limit.attempt_count + 1

        window_index = next(
            (
                i
                for i, w in enumerate(RATE_LIMIT_WINDOWS)
                if w["count"] == new_attempt_count
            ),
            len(RATE_LIMIT_WINDOWS) - 1,
        )

        expires_at = self.now + datetime.timedelta(
            minutes=RATE_LIMIT_WINDOWS[window_index]["duration"]
        )

        rate_limit.attempt_count = new_attempt_count
        rate_limit.expires_at = expires_at
        rate_limit.save(only=["attempt_count", "expires_at"])

        return expires_at

    def __clear_rate_limit(self, contact: str) -> None:
        """Clear rate limit after successful verification."""

        OTPRateLimit.delete().where(OTPRateLimit.identifier == contact).execute()

    def send(
        self, contact: str
    ) -> Tuple[Optional[Dict[str, int | str]], Optional[str]]:
        """Send OTP to the specified contact.

        Args:
            contact (str): The contact information (email or phone number).
        """
        delivery_method, err = DeliveryMethodFactory.get_delivery_method(
            contact, self.contact_type, self.action
        )
        if not delivery_method:
            return None, err

        if self.__is_rate_limited(contact):
            return None, "Too many OTP requests. Please try again later."

        expires_at = self.__increment_rate_limit(contact)

        otp = None
        fields = {
            "identifier": contact,
            "purpose": self.action.value,
            "otp_hash": None,
            "expires_at": None,
        }

        if delivery_method.self_generate_otp:
            otp = self.__generate_otp()
            otp_hash = hash_data(otp)
            fields["otp_hash"] = otp_hash
            fields["expires_at"] = self.now + datetime.timedelta(minutes=10)

        OTP.replace(**fields).execute()

        ok, err = delivery_method.send(contact, otp)

        if not ok:
            return None, err

        return {"rate_limit_expires_at": int(expires_at.timestamp())}, None

    def verify(self, contact: str, otp: str) -> Tuple[bool, Optional[str]]:
        """Verify the OTP for the specified contact.

        Args:
            contact (str): The contact information (email or phone number).
            otp (str): The OTP to be verified.
        """
        delivery_method, err = DeliveryMethodFactory.get_delivery_method(
            contact, self.contact_type, self.action
        )
        if not delivery_method:
            return False, err

        otp_record = OTP.get_or_none(
            (OTP.identifier == contact) & (OTP.purpose == self.action.value)
        )
        if not otp_record:
            return False, "OTP record not found. Request a new OTP."

        if delivery_method.self_generate_otp:
            if otp_record.is_expired():
                otp_record.delete_instance()
                return False, "OTP has expired. Request a new OTP."

            otp_record.increment_attempt_count()

            if otp_record.attempt_count > MAX_OTP_VERIFY_ATTEMPTS:
                otp_record.delete_instance()
                return False, "Too many incorrect attempts. Request a new OTP."

            if not verify_hash(otp, otp_record.otp_hash):
                return False, "Invalid OTP. Please try again."
        else:
            ok, err = delivery_method.verify(contact, otp)
            if not ok:
                return False, err

        otp_record.delete_instance()
        self.__clear_rate_limit(contact)
        return True, "OTP verified successfully."


class DeliveryMethod(ABC):
    """Abstract base class for OTP delivery methods."""

    method_name: str
    self_generate_otp: bool = False

    @abstractmethod
    def send(
        self, contact: str, otp: Optional[str] = None
    ) -> Tuple[bool, Optional[str]]:
        pass

    @abstractmethod
    def verify(self, contact: str, otp: str) -> Tuple[bool, Optional[str]]:
        pass


class MockOTPDeliveryMethod(DeliveryMethod):
    """Mock delivery method for testing."""

    method_name = "mock_otp"

    def send(
        self, contact: str, otp: Optional[str] = None
    ) -> Tuple[bool, Optional[str]]:
        """Mock send OTP."""
        return True, None

    def verify(self, contact: str, otp: str) -> Tuple[bool, Optional[str]]:
        """Mock verify OTP."""
        MOCK_OTP = "123456"

        if otp != MOCK_OTP:
            return False, "Incorrect OTP. Double-check and try again."

        return True, None


class TwilioSMSDeliveryMethod(DeliveryMethod):
    """Class for sending SMS OTPs via Twilio."""

    method_name = "twilio_sms"

    def __init__(self):
        self.client = TwilioClient(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

    def send(self, contact: str, otp: Optional[str] = None):
        """Send OTP via Twilio SMS."""
        try:
            if otp:
                message = self.client.messages.create(
                    body=otp, from_=TWILIO_PHONE_NUMBER, to=contact
                )
                status = message.status
            else:
                verification = self.client.verify.v2.services(
                    TWILIO_SERVICE_SID
                ).verifications.create(to=contact, channel="sms")
                status = verification.status

            if status in ("accepted", "pending", "queued"):
                return True, None

            return False, "Failed to send OTP. Check your number and try again."

        except TwilioRestException as e:
            logger.error("Failed to send OTP via Twilio SMS: %s", e)
            return False, "Failed to send OTP. Try again."

    def verify(self, contact: str, otp: str):
        """Verify the OTP sent via Twilio SMS."""
        try:
            verification_check = self.client.verify.v2.services(
                TWILIO_SERVICE_SID
            ).verification_checks.create(to=contact, code=otp)

            if verification_check.status == "approved":
                return True, None

            if verification_check.status == "pending":
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


class EmailDeliveryMethod(DeliveryMethod):
    """Class for sending OTPs via Email."""

    method_name = "email"
    self_generate_otp = True

    def send(self, contact: str, otp: Optional[str] = None):
        """Send OTP via Email."""
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
                "to_email": contact,
                "subject": EMAIL_SUBJECT,
                "template": "otp",
                "substitutions": {
                    "organization_name": EMAIL_ORGANIZATION_NAME,
                    "website_url": EMAIL_WEBSITE_URL,
                    "logo_url": EMAIL_LOGO_URL,
                    "project_name": EMAIL_PROJECT_NAME,
                    "expiration_time": expiration_time_words,
                    "otp_code": otp,
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
                    return True, None

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

    def verify(self, contact: str, otp: str):
        """Verify the OTP sent via Email."""
        return False, None


class QueuedroidDeliveryMethod(DeliveryMethod):
    """Class for sending SMS OTPs via Queuedroid."""

    method_name = "queuedroid"
    self_generate_otp = True

    def send(self, contact: str, otp: Optional[str] = None):
        """Send OTP via Queuedroid."""
        try:
            message = f"Your RelaySMS Verification Code is: {otp}"
            data = {
                "content": message,
                "exchange_id": QUEUEDROID_EXCHANGE_ID,
                "queue_id": QUEUEDROID_QUEUE_ID,
                "phone_number": contact,
            }
            headers = {"Authorization": f"Bearer {QUEUEDROID_API_KEY}"}
            response = requests.post(
                QUEUEDROID_API_URL, json=data, headers=headers, timeout=10
            )

            if response.ok:
                logger.info("Message sent successfully via Queuedroid.")
                return True, None

            response.raise_for_status()

            return False, "Failed to send OTP. Try again."
        except requests.RequestException as e:
            logger.error("Error sending message via Queuedroid: %s", e)
            return False, "Failed to send OTP. Try again."

    def verify(self, contact: str, otp: str):
        """Verify the OTP sent via Queuedroid."""
        return False, None


class DeliveryMethodFactory:
    """Factory class for creating delivery method instances."""

    def __get_phonenumber_details(self, phone_number: str) -> Dict[str, str]:
        """Get phonenumber details."""
        parsed_number = phonenumbers.parse(phone_number)
        region_code = geocoder.region_code_for_number(parsed_number)
        country_name = geocoder.description_for_number(parsed_number, "en")
        result = {"region_code": region_code, "country_name": country_name}
        return result

    def __is_country_allowed(self, phone_details: dict) -> bool:
        """Check if the country code of the phone number is allowed."""
        if not SMS_OTP_ALLOWED_COUNTRIES:
            return True

        country_name = phone_details["country_name"]
        region_code = phone_details["region_code"]
        if region_code not in SMS_OTP_ALLOWED_COUNTRIES:
            logger.info(
                "SMS OTP blocked for country: %s with region: %s",
                country_name,
                region_code,
            )
            return False

        return True

    def __is_delivery_method_enabled(
        self, contact_type: ContactType, action: OTPAction
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
        else:
            if not SMS_OTP_ENABLED:
                return False
            if action == OTPAction.AUTH:
                return SMS_OTP_AUTH_ENABLED
            if action == OTPAction.SIGNUP:
                return SMS_OTP_SIGNUP_ENABLED
            if action == OTPAction.RESET_PASSWORD:
                return SMS_OTP_RESET_PASSWORD_ENABLED

    @staticmethod
    def get_delivery_method(
        contact: str, contact_type: ContactType, action: OTPAction
    ) -> Tuple[Optional[DeliveryMethod], Optional[str]]:
        """Get the delivery method instance."""

        if MOCK_OTP:
            logger.warning("MOCK_OTP is enabled; skipping delivery method checks.")
            return MockOTPDeliveryMethod(), None

        factory = DeliveryMethodFactory()

        if not factory.__is_delivery_method_enabled(contact_type, action):
            action_str = f" for {action.value}" if action else ""
            method_str = "email" if contact_type == ContactType.EMAIL else "SMS"
            logger.info("%s OTP disabled%s", method_str, action_str)
            return (
                None,
                f"{method_str.upper()} OTP service unavailable for your region. Contact support.",
            )

        if contact_type == ContactType.EMAIL:
            return EmailDeliveryMethod(), None

        phone_details = factory.__get_phonenumber_details(contact)

        if not factory.__is_country_allowed(phone_details):
            return (
                None,
                "SMS OTP service unavailable for your region. Try email OTP or contact support.",
            )

        if contact_type == ContactType.PHONE:
            if (
                phone_details["region_code"]
                in QUEUEDROID_SUPPORTED_VERIFICATION_REGION_CODES
            ):
                return QueuedroidDeliveryMethod(), None
            return TwilioSMSDeliveryMethod(), None
