import requests
from config import TIMEOUT, ADVANCED_TIMEOUT

class HTTPUtils:
    @staticmethod
    def send_request(url, payload=None, method="GET", data=None, headers=None, advanced=False):
        timeout = ADVANCED_TIMEOUT if advanced else TIMEOUT
        try:
            if method == "GET":
                response = requests.get(url, params={"id": payload} if payload else None, 
                                       headers=headers, timeout=timeout)
            elif method == "POST":
                response = requests.post(url, data=data or {"input": payload}, 
                                        headers=headers, timeout=timeout)
            return response
        except requests.RequestException as e:
            return None

    @staticmethod
    def get_headers(response):
        return response.headers if response else {}
