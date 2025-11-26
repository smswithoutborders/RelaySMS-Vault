"""Test module for OTP service."""

from datetime import datetime, timedelta
import pytest
from peewee import SqliteDatabase
from src.utils import create_tables, set_configs


@pytest.fixture()
def set_testing_mode():
    """Set test mode."""
    set_configs("MODE", "testing")
    set_configs("MOCK_OTP", "True")
    set_configs("OTP_MAX_REQUESTS", "5")
    set_configs("OTP_MAX_VERIFY_ATTEMPTS", "5")
    set_configs("SMS_OTP_ENABLED", "True")
    set_configs("EMAIL_OTP_ENABLED", "True")
    set_configs("SMS_OTP_AUTH_ENABLED", "True")
    set_configs("EMAIL_OTP_AUTH_ENABLED", "True")


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

def test_send_otp_success():
    """Test successful OTP send."""
    from src.otp_service import send_otp

    phone_number = "+237123456789"
    success, message, expires = send_otp(phone_number)

    assert success is True
    assert "OTP sent" in message
    assert isinstance(expires, int)


def test_send_otp_increments_rate_limit():
    """Test rate limit increments on send."""
    from src.db_models import OTPRateLimit
    from src.otp_service import send_otp

    phone_number = "+237123456789"
    
    send_otp(phone_number)
    rate_limit = OTPRateLimit.get(OTPRateLimit.phone_number == phone_number)
    assert rate_limit.attempt_count == 1


def test_send_otp_rate_limited():
    """Test send blocked when rate limited."""
    from src.db_models import OTPRateLimit
    from src.otp_service import send_otp

    phone_number = "+237123456789"

    OTPRateLimit.create(
        phone_number=phone_number,
        attempt_count=1,
        date_expires=datetime.now() + timedelta(minutes=15),
    )

    success, message, expires = send_otp(phone_number)

    assert success is False
    assert "Too many OTP requests" in message
    assert expires is None


def test_send_otp_progressive_rate_limiting():
    """Test progressive rate limiting windows."""
    from src.db_models import OTPRateLimit
    from src.otp_service import send_otp

    phone_number = "+237123456789"

    send_otp(phone_number)
    rl = OTPRateLimit.get(OTPRateLimit.phone_number == phone_number)
    assert rl.attempt_count == 1

    rl.date_expires = datetime.now() - timedelta(minutes=1)
    rl.save()
    
    send_otp(phone_number)
    rl = OTPRateLimit.get(OTPRateLimit.phone_number == phone_number)
    assert rl.attempt_count == 2


def test_send_otp_hard_limit():
    """Test hard limit resets after expiry."""
    from src.db_models import OTPRateLimit
    from src.otp_service import send_otp

    phone_number = "+237123456789"

    OTPRateLimit.create(
        phone_number=phone_number,
        attempt_count=5,
        date_expires=datetime.now() - timedelta(minutes=1),
    )

    send_otp(phone_number)
    rl = OTPRateLimit.get(OTPRateLimit.phone_number == phone_number)
    assert rl.attempt_count == 1

def test_verify_otp_success():
    """Test successful verification."""
    from src.db_models import OTP
    from src.otp_service import verify_inapp_otp, ContactType, create_inapp_otp

    phone_number = "+237123456789"
    
    _, (otp_code, _) = create_inapp_otp(phone_number, ContactType.PHONE)
    
    success, message = verify_inapp_otp(phone_number, otp_code, ContactType.PHONE)

    assert success is True
    assert "verified successfully" in message
    
    otp_entry = OTP.get_or_none(OTP.phone_number == phone_number)
    assert otp_entry is None


def test_verify_otp_fail_closed_attempts():
    """Test attempt count increments before validation."""
    from src.db_models import OTP
    from src.otp_service import verify_inapp_otp, ContactType, create_inapp_otp

    phone_number = "+237123456789"
    
    _, (otp_code, _) = create_inapp_otp(phone_number, ContactType.PHONE)
    
    verify_inapp_otp(phone_number, "000000", ContactType.PHONE)
    otp_entry = OTP.get(OTP.phone_number == phone_number)
    assert otp_entry.attempt_count == 1
    
    verify_inapp_otp(phone_number, "111111", ContactType.PHONE)
    otp_entry = OTP.get(OTP.phone_number == phone_number)
    assert otp_entry.attempt_count == 2


def test_verify_otp_max_attempts():
    """Test OTP deleted after max attempts."""
    from src.db_models import OTP
    from src.otp_service import verify_inapp_otp, ContactType, create_inapp_otp

    phone_number = "+237123456789"
    
    _, (otp_code, _) = create_inapp_otp(phone_number, ContactType.PHONE)
    
    for _ in range(5):
        verify_inapp_otp(phone_number, "000000", ContactType.PHONE)
    
    otp_entry = OTP.get_or_none(OTP.phone_number == phone_number)
    assert otp_entry is None


def test_verify_otp_expired():
    """Test expired OTP rejected and deleted."""
    from src.db_models import OTP
    from src.otp_service import verify_inapp_otp, ContactType, create_inapp_otp

    phone_number = "+237123456789"
    
    _, (otp_code, _) = create_inapp_otp(phone_number, ContactType.PHONE)
    
    otp_entry = OTP.get(OTP.phone_number == phone_number)
    otp_entry.date_expires = datetime.now() - timedelta(minutes=1)
    otp_entry.save()
    
    success, message = verify_inapp_otp(phone_number, otp_code, ContactType.PHONE)
    
    assert success is False
    assert "expired" in message.lower()
    
    otp_entry = OTP.get_or_none(OTP.phone_number == phone_number)
    assert otp_entry is None


def test_verify_otp_no_reuse():
    """Test OTP cannot be reused."""
    from src.db_models import OTP
    from src.otp_service import verify_inapp_otp, ContactType, create_inapp_otp

    phone_number = "+237123456789"
    
    _, (otp_code, _) = create_inapp_otp(phone_number, ContactType.PHONE)
    
    success, _ = verify_inapp_otp(phone_number, otp_code, ContactType.PHONE)
    assert success is True
    
    success, message = verify_inapp_otp(phone_number, otp_code, ContactType.PHONE)
    assert success is False
    assert "No OTP record found" in message

def test_create_inapp_otp_replaces_existing():
    """Test creating OTP replaces existing."""
    from src.db_models import OTP
    from src.otp_service import ContactType, create_inapp_otp

    phone_number = "+237123456789"
    
    _, (code1, _) = create_inapp_otp(phone_number, ContactType.PHONE)
    _, (code2, _) = create_inapp_otp(phone_number, ContactType.PHONE)
    
    otp_count = OTP.select().where(OTP.phone_number == phone_number).count()
    assert otp_count == 1
    assert code1 != code2


def test_email_otp_verification():
    """Test email OTP flow."""
    from src.db_models import OTP
    from src.otp_service import verify_inapp_otp, ContactType, create_inapp_otp

    email = "test@example.com"
    
    _, (otp_code, _) = create_inapp_otp(email, ContactType.EMAIL)
    
    success, message = verify_inapp_otp(email, otp_code, ContactType.EMAIL)
    
    assert success is True
    
    otp_entry = OTP.get_or_none(OTP.email == email)
    assert otp_entry is None
