import requests

def insecure_demo():
    return requests.get('https://example.invalid', verify=False, timeout=1)
