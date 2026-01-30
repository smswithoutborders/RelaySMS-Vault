"""Comprehensive test module for OTP service."""

import datetime
from unittest.mock import Mock, patch

import pytest
from peewee import SqliteDatabase

from src.types import ContactType, OTPAction
from src.utils import create_tables, set_configs


@pytest.fixture()
def set_testing_mode():
    """Set test mode with mock OTP enabled."""
    set_configs("MODE", "testing")
    set_configs("MOCK_OTP", "True")
    set_configs("OTP_MAX_REQUESTS", "5")
    set_configs("OTP_MAX_VERIFY_ATTEMPTS", "5")
    set_configs("SMS_OTP_ENABLED", "True")
    set_configs("EMAIL_OTP_ENABLED", "True")
    set_configs("SMS_OTP_AUTH_ENABLED", "True")
    set_configs("SMS_OTP_SIGNUP_ENABLED", "True")
    set_configs("SMS_OTP_RESET_PASSWORD_ENABLED", "True")
    set_configs("EMAIL_OTP_AUTH_ENABLED", "True")
    set_configs("EMAIL_OTP_SIGNUP_ENABLED", "True")
    set_configs("EMAIL_OTP_RESET_PASSWORD_ENABLED", "True")
    set_configs("HMAC_KEY_FILE", "hashing.key")


@pytest.fixture(autouse=True)
def setup_teardown_database(tmp_path, set_testing_mode):
    """Setup and teardown test database."""
    from src.db_models import OTP, OTPRateLimit

    db_path = tmp_path / "test.db"
    test_db = SqliteDatabase(db_path)
    test_db.bind([OTP, OTPRateLimit])
    test_db.connect()
    create_tables([OTP, OTPRateLimit])

    yield

    test_db.drop_tables([OTP, OTPRateLimit])
    test_db.close()


class TestOTPServiceSend:
    """Test OTP send functionality."""

    def test_send_otp_success_phone(self):
        """Test successful OTP send to phone number."""
        from src.otp_service import OTPService

        phone = "+237123456789"
        service = OTPService(ContactType.PHONE, OTPAction.AUTH)
        result, error = service.send(phone)

        assert result is not None
        assert error is None
        assert "rate_limit_expires_at" in result

    def test_send_otp_success_email(self):
        """Test successful OTP send to email."""
        from src.otp_service import OTPService

        email = "test@example.com"
        service = OTPService(ContactType.EMAIL, OTPAction.SIGNUP)
        result, error = service.send(email)

        assert result is not None
        assert error is None

    def test_send_otp_creates_record(self):
        """Test OTP record is created in database."""
        from src.db_models import OTP
        from src.otp_service import OTPService

        phone = "+237123456789"
        service = OTPService(ContactType.PHONE, OTPAction.AUTH)
        service.send(phone)

        otp_record = OTP.get_or_none(OTP.identifier == phone)
        assert otp_record is not None
        assert otp_record.purpose == OTPAction.AUTH.value

    def test_send_otp_replaces_existing(self):
        """Test sending OTP replaces existing record."""
        from src.db_models import OTP
        from src.otp_service import OTPService

        phone = "+237123456789"
        service = OTPService(ContactType.PHONE, OTPAction.AUTH)
        service.send(phone)
        service.send(phone)

        otp_count = OTP.select().where(OTP.identifier == phone).count()
        assert otp_count == 1


class TestOTPServiceVerify:
    """Test OTP verification functionality."""

    def test_verify_otp_success(self):
        """Test successful OTP verification."""
        from src.db_models import OTP
        from src.otp_service import OTPService

        phone = "+237123456789"
        service = OTPService(ContactType.PHONE, OTPAction.AUTH)
        service.send(phone)

        success, message = service.verify(phone, "123456")
        assert success is True
        assert "verified successfully" in message.lower()

        otp_record = OTP.get_or_none(OTP.identifier == phone)
        assert otp_record is None

    def test_verify_otp_invalid_code(self):
        """Test verification fails with invalid OTP."""
        from src.otp_service import OTPService

        phone = "+237123456789"
        service = OTPService(ContactType.PHONE, OTPAction.AUTH)
        service.send(phone)

        success, message = service.verify(phone, "000000")
        assert success is False
        assert "incorrect" in message.lower()

    def test_verify_otp_no_record(self):
        """Test verification fails when no OTP record exists."""
        from src.otp_service import OTPService

        phone = "+237123456789"
        service = OTPService(ContactType.PHONE, OTPAction.AUTH)

        success, message = service.verify(phone, "123456")
        assert success is False
        assert "not found" in message.lower()

    @patch("src.otp_service.MOCK_OTP", False)
    @patch("src.otp_service.EMAIL_OTP_ENABLED", True)
    def test_verify_otp_expired(self):
        """Test verification fails for expired OTP."""
        from src.db_models import OTP
        from src.otp_service import OTPService

        email = "test@example.com"
        service = OTPService(ContactType.EMAIL, OTPAction.AUTH)
        service.send(email)

        otp_record = OTP.get(OTP.identifier == email)
        otp_record.expires_at = datetime.datetime.now() - datetime.timedelta(minutes=1)
        otp_record.save()

        success, message = service.verify(email, "123456")
        assert success is False
        assert "expired" in message.lower()

    @patch("src.otp_service.MOCK_OTP", False)
    @patch("src.otp_service.EMAIL_OTP_ENABLED", True)
    def test_verify_otp_max_attempts(self):
        """Test OTP deleted after max verification attempts."""
        from src.db_models import OTP
        from src.otp_service import OTPService

        email = "test@example.com"
        service = OTPService(ContactType.EMAIL, OTPAction.AUTH)
        service.send(email)

        for _ in range(6):
            service.verify(email, "000000")

        otp_record = OTP.get_or_none(OTP.identifier == email)
        assert otp_record is None

    @patch("src.otp_service.MOCK_OTP", False)
    @patch("src.otp_service.EMAIL_OTP_ENABLED", True)
    def test_verify_otp_increments_attempts(self):
        """Test attempt count increments on wrong OTP."""
        from src.db_models import OTP
        from src.otp_service import OTPService

        email = "test@example.com"
        service = OTPService(ContactType.EMAIL, OTPAction.AUTH)
        service.send(email)

        service.verify(email, "000000")
        otp_record = OTP.get(OTP.identifier == email)
        assert otp_record.attempt_count == 1


class TestRateLimiting:
    """Test rate limiting functionality."""

    def test_rate_limit_created_on_send(self):
        """Test rate limit record created on first send."""
        from src.db_models import OTPRateLimit
        from src.otp_service import OTPService

        phone = "+237123456789"
        service = OTPService(ContactType.PHONE, OTPAction.AUTH)
        service.send(phone)

        rate_limit = OTPRateLimit.get_or_none(OTPRateLimit.identifier == phone)
        assert rate_limit is not None
        assert rate_limit.attempt_count == 1

    def test_rate_limit_blocks_send(self):
        """Test rate limit blocks OTP send."""
        from src.db_models import OTPRateLimit
        from src.otp_service import OTPService

        phone = "+237123456789"
        OTPRateLimit.create(
            identifier=phone,
            attempt_count=1,
            expires_at=datetime.datetime.now() + datetime.timedelta(minutes=5),
        )

        service = OTPService(ContactType.PHONE, OTPAction.AUTH)
        result, error = service.send(phone)

        assert result is None
        assert "too many" in error.lower()

    def test_rate_limit_expires(self):
        """Test expired rate limit allows send."""
        from src.db_models import OTPRateLimit
        from src.otp_service import OTPService

        phone = "+237123456789"
        OTPRateLimit.create(
            identifier=phone,
            attempt_count=1,
            expires_at=datetime.datetime.now() - datetime.timedelta(minutes=1),
        )

        service = OTPService(ContactType.PHONE, OTPAction.AUTH)
        result, error = service.send(phone)

        assert result is not None
        assert error is None

    def test_rate_limit_progressive_windows(self):
        """Test progressive rate limiting increases duration."""
        from src.db_models import OTPRateLimit
        from src.otp_service import OTPService

        phone = "+237123456789"
        service = OTPService(ContactType.PHONE, OTPAction.AUTH)

        service.send(phone)
        rl = OTPRateLimit.get(OTPRateLimit.identifier == phone)
        first_attempt = rl.attempt_count
        first_expires = rl.expires_at

        rl.expires_at = datetime.datetime.now() - datetime.timedelta(minutes=1)
        rl.save()

        service.send(phone)
        rl = OTPRateLimit.get(OTPRateLimit.identifier == phone)
        assert rl.attempt_count > first_attempt
        assert rl.expires_at > first_expires

    def test_rate_limit_cleared_on_verify(self):
        """Test rate limit cleared after successful verification."""
        from src.db_models import OTPRateLimit
        from src.otp_service import OTPService

        phone = "+237123456789"
        service = OTPService(ContactType.PHONE, OTPAction.AUTH)
        service.send(phone)
        service.verify(phone, "123456")

        rate_limit = OTPRateLimit.get_or_none(OTPRateLimit.identifier == phone)
        assert rate_limit is None


class TestOTPActions:
    """Test different OTP action types."""

    def test_otp_action_auth(self):
        """Test OTP for authentication action."""
        from src.db_models import OTP
        from src.otp_service import OTPService

        phone = "+237123456789"
        service = OTPService(ContactType.PHONE, OTPAction.AUTH)
        service.send(phone)

        otp_record = OTP.get(OTP.identifier == phone)
        assert otp_record.purpose == "auth"

    def test_otp_action_signup(self):
        """Test OTP for signup action."""
        from src.db_models import OTP
        from src.otp_service import OTPService

        phone = "+237123456789"
        service = OTPService(ContactType.PHONE, OTPAction.SIGNUP)
        service.send(phone)

        otp_record = OTP.get(OTP.identifier == phone)
        assert otp_record.purpose == "signup"

    def test_otp_action_reset_password(self):
        """Test OTP for reset password action."""
        from src.db_models import OTP
        from src.otp_service import OTPService

        email = "test@example.com"
        service = OTPService(ContactType.EMAIL, OTPAction.RESET_PASSWORD)
        service.send(email)

        otp_record = OTP.get(OTP.identifier == email)
        assert otp_record.purpose == "reset_password"

    def test_verify_otp_wrong_action(self):
        """Test verification fails with wrong action."""
        from src.otp_service import OTPService

        phone = "+237123456789"
        send_service = OTPService(ContactType.PHONE, OTPAction.AUTH)
        send_service.send(phone)

        verify_service = OTPService(ContactType.PHONE, OTPAction.SIGNUP)
        success, message = verify_service.verify(phone, "123456")

        assert success is False
        assert "not found" in message.lower()


class TestDeliveryMethods:
    """Test delivery method functionality."""

    def test_mock_otp_delivery(self):
        """Test mock OTP delivery method."""
        from src.otp_service import MockOTPDeliveryMethod

        mock = MockOTPDeliveryMethod()
        success, error = mock.send("+237123456789", "123456")

        assert success is True
        assert error is None

    def test_mock_otp_verify_correct(self):
        """Test mock OTP verifies correct code."""
        from src.otp_service import MockOTPDeliveryMethod

        mock = MockOTPDeliveryMethod()
        success, error = mock.verify("+237123456789", "123456")

        assert success is True

    def test_mock_otp_verify_incorrect(self):
        """Test mock OTP rejects incorrect code."""
        from src.otp_service import MockOTPDeliveryMethod

        mock = MockOTPDeliveryMethod()
        success, error = mock.verify("+237123456789", "000000")

        assert success is False
        assert error is not None

    @patch("src.otp_service.EMAIL_SERVICE_URL", "http://test.com")
    @patch("src.otp_service.EMAIL_SERVICE_API_KEY", "test_key")
    @patch("requests.post")
    def test_email_delivery_success(self, mock_post):
        """Test email delivery method success."""
        from src.otp_service import EmailDeliveryMethod

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"success": True}
        mock_post.return_value = mock_response

        email_method = EmailDeliveryMethod()
        success, error = email_method.send("test@example.com", "123456")

        assert success is True
        assert error is None
        mock_post.assert_called_once()

    @patch("src.otp_service.QUEUEDROID_API_URL", "http://test.com")
    @patch("src.otp_service.QUEUEDROID_API_KEY", "test_key")
    @patch("requests.post")
    def test_queuedroid_delivery_success(self, mock_post):
        """Test Queuedroid delivery method success."""
        from src.otp_service import QueuedroidDeliveryMethod

        mock_response = Mock()
        mock_response.ok = True
        mock_post.return_value = mock_response

        qd_method = QueuedroidDeliveryMethod()
        success, error = qd_method.send("+237123456789", "123456")

        assert success is True
        assert error is None


class TestDeliveryMethodFactory:
    """Test delivery method factory."""

    def test_factory_returns_mock_when_enabled(self):
        """Test factory returns mock delivery when MOCK_OTP enabled."""
        from src.otp_service import DeliveryMethodFactory, MockOTPDeliveryMethod

        method, error = DeliveryMethodFactory.get_delivery_method(
            "+237123456789", ContactType.PHONE, OTPAction.AUTH
        )

        assert isinstance(method, MockOTPDeliveryMethod)
        assert error is None

    @patch("src.otp_service.MOCK_OTP", False)
    @patch("src.otp_service.EMAIL_OTP_ENABLED", True)
    @patch("src.otp_service.EMAIL_OTP_AUTH_ENABLED", True)
    def test_factory_returns_email_method(self):
        """Test factory returns email delivery method."""
        from src.otp_service import DeliveryMethodFactory, EmailDeliveryMethod

        method, error = DeliveryMethodFactory.get_delivery_method(
            "test@example.com", ContactType.EMAIL, OTPAction.AUTH
        )

        assert isinstance(method, EmailDeliveryMethod)
        assert error is None

    @patch("src.otp_service.MOCK_OTP", False)
    @patch("src.otp_service.SMS_OTP_ENABLED", False)
    def test_factory_disabled_sms_method(self):
        """Test factory returns error when SMS disabled."""
        from src.otp_service import DeliveryMethodFactory

        method, error = DeliveryMethodFactory.get_delivery_method(
            "+237123456789", ContactType.PHONE, OTPAction.AUTH
        )

        assert method is None
        assert error is not None
        assert "unavailable" in error.lower()

    @patch("src.otp_service.MOCK_OTP", False)
    @patch("src.otp_service.EMAIL_OTP_ENABLED", False)
    def test_factory_disabled_email_method(self):
        """Test factory returns error when email disabled."""
        from src.otp_service import DeliveryMethodFactory

        method, error = DeliveryMethodFactory.get_delivery_method(
            "test@example.com", ContactType.EMAIL, OTPAction.SIGNUP
        )

        assert method is None
        assert error is not None


class TestOTPGeneration:
    """Test OTP generation."""

    @patch("src.otp_service.MOCK_OTP", False)
    @patch("src.otp_service.EMAIL_OTP_ENABLED", True)
    def test_otp_hash_stored(self):
        """Test OTP hash is stored in database for self-generated OTPs."""
        from src.db_models import OTP
        from src.otp_service import OTPService

        email = "test@example.com"
        service = OTPService(ContactType.EMAIL, OTPAction.AUTH)
        service.send(email)

        otp_record = OTP.get(OTP.identifier == email)
        assert otp_record.otp_hash is not None

    @patch("src.otp_service.MOCK_OTP", False)
    @patch("src.otp_service.EMAIL_OTP_ENABLED", True)
    def test_otp_expiry_set(self):
        """Test OTP expiry is set correctly for self-generated OTPs."""
        from src.db_models import OTP
        from src.otp_service import OTPService

        email = "test@example.com"
        service = OTPService(ContactType.EMAIL, OTPAction.AUTH)
        service.send(email)

        otp_record = OTP.get(OTP.identifier == email)
        assert otp_record.expires_at is not None
        assert otp_record.expires_at > datetime.datetime.now()
