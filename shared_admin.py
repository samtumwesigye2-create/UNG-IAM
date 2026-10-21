"""Validate the configured administrator against the Grid master authority.

No password copies or successful-authentication caches are kept in JANUS.
"""
import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, HTTPRedirectHandler, build_opener
from fastapi import HTTPException

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def open_request(request):
    return build_opener(NoRedirect()).open(request, timeout=5)

def verify_master(base_url, password):
    parsed = urlsplit(base_url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise HTTPException(503, 'Shared sign-in is not configured correctly')
    if not password or '\r' in password or '\n' in password:
        raise HTTPException(401, 'Invalid credentials')
    request = Request(base_url.rstrip('/') + '/vector5250/profiles/bootstrap', data=b'', method='POST', headers={'X-Access-Code': password})
    try:
        with open_request(request) as response:
            payload = json.loads(response.read(4096))
        if not isinstance(payload, dict) or type(payload.get('profile_count')) is not int or payload['profile_count'] < 0 or type(payload.get('bootstrap_required')) is not bool:
            raise ValueError('Unexpected authority response')
    except HTTPError as exc:
        if exc.code in (401, 403):
            raise HTTPException(401, 'Invalid credentials') from None
        raise HTTPException(503, 'Shared sign-in is temporarily unavailable') from None
    except (URLError, OSError, ValueError):
        raise HTTPException(503, 'Shared sign-in is temporarily unavailable') from None
    return True
