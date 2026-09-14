import io
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from fastapi import HTTPException
import shared_admin as shared

class SharedSigninTests(unittest.TestCase):
    def test_master_verified_by_authority(self):
        with patch.object(shared, 'open_request', return_value=io.BytesIO(b'{"profile_count":2,"bootstrap_required":false}')):
            self.assertTrue(shared.verify_master('https://identity.example', 'example-code'))

    def test_invalid_code_rejected(self):
        with patch.object(shared, 'open_request', side_effect=HTTPError('url',403,'denied',{},None)):
            with self.assertRaises(HTTPException) as raised:
                shared.verify_master('https://identity.example', 'bad')
            self.assertEqual(raised.exception.status_code,401)

    def test_outage_fails_closed(self):
        with patch.object(shared, 'open_request', side_effect=URLError('offline')):
            with self.assertRaises(HTTPException) as raised:
                shared.verify_master('https://identity.example', 'example-code')
            self.assertEqual(raised.exception.status_code,503)

    def test_html_or_unexpected_response_is_not_authentication(self):
        for body in (b'<html>login</html>', b'{}', b'{"profile_count":true,"bootstrap_required":false}'):
            with patch.object(shared, 'open_request', return_value=io.BytesIO(body)):
                with self.assertRaises(HTTPException):
                    shared.verify_master('https://identity.example', 'example-code')

    def test_insecure_authority_rejected(self):
        with self.assertRaises(HTTPException):
            shared.verify_master('http://identity.example', 'example-code')

    def test_redirect_rejected(self):
        with patch.object(shared, 'open_request', side_effect=HTTPError('url',302,'redirect',{},None)):
            with self.assertRaises(HTTPException) as raised:
                shared.verify_master('https://identity.example', 'example-code')
            self.assertEqual(raised.exception.status_code,503)
