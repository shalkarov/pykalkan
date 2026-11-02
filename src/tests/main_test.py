import os
import time

import pytest
from dotenv import load_dotenv

from pykalkan import *

load_dotenv()

LIBRARY = "libkalkancryptwr-64.so"
DATA_TO_SIGN = "SGVsbG8sIFdvcmxkIQ=="
XML_TO_SIGN = '<?xml version="1.0" encoding="UTF-8"?>\n<root>\n    <data>Hello, World!</data>\n</root>\n'
CERT_PATH = os.getenv("CERT_PATH")
CERT_PASSWORD = os.getenv("CERT_PASSWORD")
TSA_URL = "http://test.pki.gov.kz/tsp/"
OCSP_URL = "http://test.pki.gov.kz/ocsp/"


def is_valid_date(timestamp):
    try:
        timestamp = int(timestamp)
        time.gmtime(timestamp)
        return True
    except ValueError:
        return False


@pytest.fixture(scope="module")
def adapter():
    try:
        with Adapter(LIBRARY) as kc:
            kc.load_key_store(CERT_PATH, CERT_PASSWORD)
            kc.set_tsa_url(TSA_URL)
            yield kc
    except OSError as e:
        assert False, f"Adapter creation fail: {e}"
    except Exception as e:
        pytest.fail(str(e))


def test_sign_data(adapter):
    try:
        data = adapter.sign_data(DATA_TO_SIGN)
        assert data is not None, "Data signing failed"
        timestamp = adapter.get_time_from_sign(data.decode())
        assert is_valid_date(timestamp), "Invalid time in signed data"
    except exceptions.KalkanException as err:
        pytest.fail(str(err))


def test_verify_data(adapter):
    try:
        data = adapter.sign_data(DATA_TO_SIGN)
    except exceptions.KalkanException as err:
        pytest.fail(str(err))
    try:
        adapter.verify_data(data.decode(), DATA_TO_SIGN)
    except exceptions.ValidateException as err:
        pytest.fail(str(err))


def test_validate_cert_ocsp(adapter):
    try:
        data = adapter.sign_data(DATA_TO_SIGN)
    except exceptions.KalkanException as err:
        pytest.fail(str(err))
    try:
        res = adapter.verify_data(data.decode(), DATA_TO_SIGN)
        adapter.x509_validate_certificate_ocsp(res["Cert"].decode(), OCSP_URL)
    except exceptions.ValidateException as err:
        pytest.fail(str(err))


def test_validate_cert_crl(adapter):
    try:
        data = adapter.sign_data(DATA_TO_SIGN)
    except exceptions.KalkanException as err:
        pytest.fail(str(err))
    try:
        res = adapter.verify_data(data.decode(), DATA_TO_SIGN)
        adapter.x509_validate_certificate_crl(res["Cert"].decode(), os.getenv("CRL_PATH"))
    except exceptions.ValidateException as err:
        pytest.fail(str(err))


def test_sign_xml(adapter):
    try:
        signed = adapter.sign_xml(XML_TO_SIGN).decode()
    except exceptions.KalkanException as err:
        pytest.fail(str(err))
    assert "<ds:Signature" in signed, "Signature not found in signed XML"
    assert "Hello, World!" in signed, "Original data lost in signed XML"


def test_verify_xml(adapter):
    try:
        signed = adapter.sign_xml(XML_TO_SIGN)
    except exceptions.KalkanException as err:
        pytest.fail(str(err))
    try:
        adapter.verify_xml(signed.decode())
    except exceptions.ValidateException as err:
        pytest.fail(str(err))


def test_verify_xml_tampered(adapter):
    try:
        signed = adapter.sign_xml(XML_TO_SIGN)
    except exceptions.KalkanException as err:
        pytest.fail(str(err))
    tampered = signed.decode().replace("Hello, World!", "Hello, Kalkan!", 1)
    with pytest.raises(exceptions.ValidateException):
        adapter.verify_xml(tampered)
