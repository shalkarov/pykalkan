import pytest
from pykalkan import Adapter, exceptions
from pykalkan.enums import SignatureFlag, CertProp, CertCode

DATA_TO_SIGN = "SGVsbG8sIFdvcmxkIQ=="
XML_TO_SIGN = "<root><data>Hello</data></root>"


@pytest.fixture
def adapter(mock_lib):
    with Adapter(mock_lib) as kc:
        kc.load_key_store("/fake/cert.p12", "password")
        kc.set_tsa_url()
        yield kc


# ── Lifecycle ────────────────────────────────────────────────────────────────

def test_adapter_init(mock_lib):
    with Adapter(mock_lib) as kc:
        assert kc is not None


def test_adapter_context_manager_cleanup(mock_lib):
    from pykalkan.adapter import Adapter as A
    with A(mock_lib) as kc:
        pass
    assert A._instance is None


# ── sign_data ────────────────────────────────────────────────────────────────

def test_sign_data_returns_bytes(adapter):
    result = adapter.sign_data(DATA_TO_SIGN)
    assert isinstance(result, bytes)
    assert len(result) > 0


def test_sign_data_custom_flags(adapter):
    result = adapter.sign_data(
        DATA_TO_SIGN,
        flags=(SignatureFlag.KC_SIGN_CMS, SignatureFlag.KC_IN_BASE64, SignatureFlag.KC_OUT_BASE64),
    )
    assert isinstance(result, bytes)


# ── verify_data ──────────────────────────────────────────────────────────────

def test_verify_data_returns_dict(adapter):
    signed = adapter.sign_data(DATA_TO_SIGN)
    result = adapter.verify_data(signed.decode(), DATA_TO_SIGN)
    assert isinstance(result, dict)
    assert "Cert" in result
    assert "Info" in result
    assert "Data" in result


# ── sign_xml ─────────────────────────────────────────────────────────────────

def test_sign_xml_returns_bytes(adapter):
    result = adapter.sign_xml(XML_TO_SIGN)
    assert isinstance(result, bytes)
    assert len(result) > 0


def test_sign_xml_custom_flags(adapter):
    result = adapter.sign_xml(
        XML_TO_SIGN,
        flags=(SignatureFlag.KC_SIGN_DRAFT, SignatureFlag.KC_WITH_CERT),
    )
    assert isinstance(result, bytes)


# ── verify_xml ───────────────────────────────────────────────────────────────

def test_verify_xml_returns_dict(adapter):
    signed = adapter.sign_xml(XML_TO_SIGN)
    result = adapter.verify_xml(signed.decode())
    assert isinstance(result, dict)
    assert "Info" in result


# ── Certificate operations ───────────────────────────────────────────────────

def test_export_certificate_from_store(adapter):
    cert = adapter.x509_export_certificate_from_store()
    assert isinstance(cert, bytes)
    assert len(cert) > 0


def test_certificate_get_info(adapter):
    cert = adapter.x509_export_certificate_from_store()
    info = adapter.x509_certificate_get_info(cert.decode(), CertProp.KC_SUBJECT_COMMONNAME)
    assert isinstance(info, bytes)


def test_load_certificate_from_buffer(adapter):
    cert = adapter.x509_export_certificate_from_store()
    adapter.x509_load_certificate_from_buffer(cert.decode(), CertCode.KC_CERT_B64)


# ── Timestamp ────────────────────────────────────────────────────────────────

def test_get_time_from_sign(adapter):
    signed = adapter.sign_data(DATA_TO_SIGN)
    timestamp = adapter.get_time_from_sign(signed.decode())
    assert isinstance(timestamp, int)
    assert timestamp > 0


# ── Certificate validation ───────────────────────────────────────────────────

def test_validate_certificate_ocsp(adapter):
    cert = adapter.x509_export_certificate_from_store()
    result = adapter.x509_validate_certificate_ocsp(cert.decode())
    assert isinstance(result, dict)
    assert "info" in result


def test_validate_certificate_crl(adapter):
    cert = adapter.x509_export_certificate_from_store()
    result = adapter.x509_validate_certificate_crl(cert.decode(), "/fake/crl.crl")
    assert isinstance(result, dict)
    assert "info" in result


# ── Error handling ───────────────────────────────────────────────────────────

def test_kalkan_exception_on_error(mock_lib):
    from unittest.mock import patch, MagicMock
    from pykalkan.C.lib_handle import LibHandle
    from pykalkan.adapter import Adapter as A

    LibHandle._LibHandle__instance = None
    A._instance = None

    mock_handle = MagicMock()
    mock_handle.Init.return_value = 1
    mock_handle.KC_GetLastErrorString.return_value = b"Test error"

    with patch("ctypes.CDLL", return_value=mock_handle):
        with pytest.raises(exceptions.KalkanException):
            with A(mock_lib) as kc:
                pass

    LibHandle._LibHandle__instance = None
    A._instance = None
