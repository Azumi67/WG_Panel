
from __future__ import annotations
import json
from urllib.parse import urlsplit
import requests


def validate_base_url(base_url):
    base = str(base_url or '').strip().rstrip('/')
    if not base or '\\' in base or any(ord(c)<33 or ord(c)==127 for c in base):
        raise ValueError('Invalid node URL.')
    parsed = urlsplit(base)
    if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
        raise ValueError('Invalid node URL.')
    _ = parsed.port
    return base


def _url(base_url: str, path: str) -> str:
    base = validate_base_url(base_url)
    rel = str(path or '').lstrip('/')
    return f"{base}/{rel}"


def _check_response(response, *, mutation=False):
    if 300 <= response.status_code < 400:
        raise requests.HTTPError('Node redirects are not permitted. Configure its final URL.',response=response)
    response.raise_for_status()
    result = decode_response(response)
    if mutation and (not isinstance(result, dict) or result.get('ok') is False or result.get('error')):
        raise requests.HTTPError('Node did not confirm the requested mutation. Check its current state before retrying.', response=response)
    return result


def decode_response(response):
    ctype = (response.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
    if ctype == "application/json" or ctype.endswith("+json"):
        try:
            return response.json()
        except ValueError:
            return response.text
    text = response.text
    stripped = (text or "").lstrip()
    if stripped[:1] in "{[":
        try:
            return json.loads(text)
        except ValueError:
            pass
    return text


def _headers(api_key: str, *, json_body: bool = False) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {str(api_key or '').strip()}"}
    if json_body:
        headers["Content-Type"] = "application/json"
    return headers


def get(base_url: str, path: str, api_key: str, *, timeout: float = 6):
    response = requests.get(_url(base_url, path), headers=_headers(api_key), timeout=timeout, allow_redirects=False)
    return _check_response(response)


def post(base_url: str, path: str, api_key: str, payload=None, *, timeout: float = 30):
    response = requests.post(
        _url(base_url, path), headers=_headers(api_key, json_body=True),
        json=payload or {}, timeout=timeout, allow_redirects=False,
    )
    return _check_response(response, mutation=True)


def delete(base_url: str, path: str, api_key: str, payload=None, *, timeout: float = 30):
    kwargs = {"headers": _headers(api_key), "timeout": timeout, "allow_redirects": False}
    if payload is not None:
        kwargs["headers"]["Content-Type"] = "application/json"
        kwargs["json"] = payload
    response = requests.delete(_url(base_url, path), **kwargs)
    return _check_response(response, mutation=True)
