import ctypes
from unittest.mock import MagicMock, patch
import pytest

SIGNED_DATA = b"SIGNED_BASE64_DATA"
SIGNED_XML = b"<SignedXml><Signature>...</Signature></SignedXml>"
CERT_BYTES = b"CERT_DATA"
VERIFY_INFO = b"OK"


def make_mock_handle():
    """Creates a mock ctypes CDLL handle that simulates KalkanCrypt responses."""
    handle = MagicMock()

    handle.Init.return_value = 0
    handle.KC_Finalize.return_value = None
    handle.KC_LoadKeyStore.return_value = 0
    handle.KC_TSASetUrl.return_value = None

    def mock_sign_data(alias, flags, data, data_len, in_sig, in_sig_len, out, out_len):
        ctypes.memmove(out, SIGNED_DATA, len(SIGNED_DATA))
        return 0

    handle.SignData.side_effect = mock_sign_data

    def mock_sign_xml(alias, flags, in_xml, in_xml_len, out, out_len, node_id, parent, ns):
        ctypes.memmove(out, SIGNED_XML, len(SIGNED_XML))
        return 0

    handle.SignXML.side_effect = mock_sign_xml

    def mock_verify_data(alias, flags, data, data_len, sign, sign_len,
                         out_data, out_data_len, out_info, out_info_len,
                         cert_id, out_cert, out_cert_len):
        ctypes.memmove(out_info, VERIFY_INFO, len(VERIFY_INFO))
        ctypes.memmove(out_cert, CERT_BYTES, len(CERT_BYTES))
        return 0

    handle.VerifyData.side_effect = mock_verify_data

    def mock_verify_xml(alias, flags, in_xml, in_xml_len, out, out_len):
        ctypes.memmove(out, VERIFY_INFO, len(VERIFY_INFO))
        return 0

    handle.VerifyXML.side_effect = mock_verify_xml

    def mock_export_cert(alias, flags, out, out_len):
        ctypes.memmove(out, CERT_BYTES, len(CERT_BYTES))
        return 0

    handle.X509ExportCertificateFromStore.side_effect = mock_export_cert

    def mock_cert_info(cert, cert_len, prop, out, out_len):
        value = b"TestValue"
        ctypes.memmove(out, value, len(value))
        return 0

    handle.X509CertificateGetInfo.side_effect = mock_cert_info

    handle.X509LoadCertificateFromBuffer.return_value = 0

    def mock_validate(cert, cert_len, valid_type, valid_path, check_time,
                      out_info, out_info_len, flag, resp, resp_len):
        ctypes.memmove(out_info, VERIFY_INFO, len(VERIFY_INFO))
        return 0

    handle.X509ValidateCertificate.side_effect = mock_validate

    def mock_get_time(data, data_len, flags, sig_id, out_time):
        out_time.contents.value = 1700000000
        return 0

    handle.KC_GetTimeFromSig.side_effect = mock_get_time

    return handle


@pytest.fixture
def mock_lib(tmp_path):
    """Patch ctypes.CDLL to return a mock handle. Resets Adapter singleton."""
    from pykalkan.C.lib_handle import LibHandle
    from pykalkan.adapter import Adapter

    LibHandle._LibHandle__instance = None
    Adapter._instance = None

    lib_path = str(tmp_path / "libkalkancryptwr-64.so")
    open(lib_path, "w").close()

    mock_handle = make_mock_handle()

    with patch("ctypes.CDLL", return_value=mock_handle):
        yield lib_path

    LibHandle._LibHandle__instance = None
    Adapter._instance = None
