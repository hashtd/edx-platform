"""
Wrapper to use pwnedpassword Service
"""


import logging

import requests
from django.conf import settings
from requests.exceptions import ReadTimeout
from rest_framework.status import HTTP_408_REQUEST_TIMEOUT

from openedx.core.djangoapps.site_configuration import helpers as configuration_helpers

API_URL = configuration_helpers.get_value('PWNED_PASSWORD_API_URL', settings.PWNED_PASSWORD_API_URL)
log = logging.getLogger(__name__)


def convert_password_tuple(value):
    """
    a conversion function used to convert a string to a tuple
    """
    signature, count = value.split(":")
    return (signature, int(count))


class PwnedPasswordsAPI:
    """
    WrapperClass on pwned password service
    to fetch similar password signatures
    along with their count
    """

    @staticmethod
    def range(password):
        """
        Returns a dict containing hashed password signatures along with their count

        **Argument(s):
            password: a sha-1-hashed string against which pwnedservice is invoked

        **Returns:
            {
                "7ecd77ecd7": 341,
                "7ecd77ecd77ecd7": 12,
            }
        """
        range_url = API_URL + '/range/{}'.format(password[:5])

        try:
            response = requests.get(range_url, timeout=5)
            entries = dict(map(convert_password_tuple, response.text.split("\r\n")))
            return entries

        except ReadTimeout:
            log.warning('Request timed out for {}'.format(password))
            return HTTP_408_REQUEST_TIMEOUT
