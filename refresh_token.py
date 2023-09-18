import logging
import requests
import json
from html.parser import HTMLParser

_LOGGER = logging.getLogger(__name__)

def get_refresh_token(uname, pwd, BASE_URL, LOGIN):
    _cookie = None
    _token = None
    _json = None
    config = {
                "username": uname,
                "password": pwd
    }
    
    try:
        _session = requests.session()
        _r = _session.get(url=LOGIN)
    except Exception as e:
        _LOGGER.error(str(e))
    else:
        _cookie = _r.cookies
        parser = Parse()
        parser.feed(_r.text)
        _action = parser.data

        _payload = {'username': config['username'],
                    'password': config['password'],
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'origin': BASE_URL,
                    'referer': LOGIN,
                    'X-Requested-With': 'XMLHttpRequest'}
        try:
            _r = _session.post(url=_action, data=_payload, cookies=_cookie, allow_redirects=False)
        except Exception as e:
            _LOGGER.error(str(e))
        else:
            _ondus_url = _r.next.url.replace('ondus', 'https')
            try:
                _r = _session.get(url=_ondus_url, cookies=_cookie)
            except Exception as e:
                _LOGGER.error(str(e))
            else:
                _json = json.loads(_r.text)

    return _json

class Parse(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self.data = []
        
    def handle_starttag(self, tag, attrs):
        if tag == "form":
            for name, value in attrs:
                if name == 'action':
                    self.data = value
