import pytest
from src.smb.session import SMBSession

def test_smb_session_initialization():
    session = SMBSession(username="admin", password="password123", domain="WORKGROUP")
    assert session.username == "admin"
    assert session.password == "password123"
    assert session.domain == "WORKGROUP"
    assert session.is_anonymous is False

def test_smb_session_anonymous():
    session = SMBSession()
    assert session.username == ""
    assert session.is_anonymous is True

def test_smb_session_guest():
    session = SMBSession(use_guest=True)
    assert session.use_guest is True
    assert session.is_anonymous is True
