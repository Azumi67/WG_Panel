"""Authenticated HTTP client for WG Panel remote nodes"""
from __future__ import annotations
import json
import requests


def _url(base_url: str, path: str) -> str:

    base = str(base_url or "").rstrip("/")
    rel = str(path or "").lstrip("/")
    return f"{base}/{rel}"


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
    response = requests.get(_url(base_url, path), headers=_headers(api_key), timeout=timeout)
    response.raise_for_status()
    return decode_response(response)


def post(base_url: str, path: str, api_key: str, payload=None, *, timeout: float = 8):
    response = requests.post(
        _url(base_url, path), headers=_headers(api_key, json_body=True),
        json=payload or {}, timeout=timeout,
    )
    response.raise_for_status()
    return decode_response(response)


def delete(base_url: str, path: str, api_key: str, payload=None, *, timeout: float = 8):
    kwargs = {"headers": _headers(api_key), "timeout": timeout}
    if payload is not None:
        kwargs["headers"]["Content-Type"] = "application/json"
        kwargs["json"] = payload
    response = requests.delete(_url(base_url, path), **kwargs)
    response.raise_for_status()
    return decode_response(response)
