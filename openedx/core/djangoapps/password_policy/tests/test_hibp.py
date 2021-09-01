"""
Test 'have i been pwned' password service
"""


from unittest.mock import Mock, patch

from django.test import TestCase
from requests.exceptions import ReadTimeout
from testfixtures import LogCapture

from openedx.core.djangoapps.password_policy.hibp import PwnedPasswordsAPI, log


class TestPwnedPasswordsService(TestCase):
    """
    Tests pwned password service
    """
    @patch('requests.get')
    def test_matched_pwned_passwords(self, mock_get):
        """
        Test that pwned service returns pwned passwords dict
        """
        response_string = "7ecd77ecd7:341\r\n7ecd77ecd77ecd7:12"
        pwned_password = {
            "7ecd77ecd7": 341,
            "7ecd77ecd77ecd7": 12,
        }
        response = Mock()
        response.text = response_string
        mock_get.return_value = response
        response = PwnedPasswordsAPI.range('7ecd7')

        self.assertEqual(response, pwned_password)

    @patch('requests.get', side_effect=ReadTimeout)
    def test_warning_log_on_timeout(self, mock_get):  # pylint: disable=unused-argument
        """
        Test that captures the warning log on timeout
        """
        with LogCapture(log.name) as log_capture:
            PwnedPasswordsAPI.range('7ecd7')
            log_capture.check_present(
                (
                    log.name,
                    'WARNING',
                    'Request timed out against 7ecd7'
                )
            )
        assert 'Request timed out against 7ecd7' in log_capture.records[0].getMessage()
