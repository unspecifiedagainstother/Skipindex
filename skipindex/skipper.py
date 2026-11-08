from __future__ import annotations

import re
import time
from typing import Optional

try:
    from curl_cffi import requests as _cf
except ImportError as exc:
    raise ImportError("pip install curl_cffi") from exc

from .exceptions import GateError
from ._crypto import xor_decrypt

_REVEAL_URL = "https://pasteindex.com/reveal.php"

class PasteIndexSkipper:
    """
    Parameters
    ----------
    impersonate : str
        curl_cffi browser fingerprint. Default: ``"chrome131"``.
    wait_override : int, optional
        Fixed inter-step delay in seconds. Overrides the server suggestion.
    max_wait : int
        Cap on server-suggested wait time. Default: ``10``.
    timeout : int
        Per-request timeout in seconds. Default: ``20``.

    Examples
    --------
    >>> from skippaste import PasteIndexSkipper
    >>> s = PasteIndexSkipper()
    >>> print(s.skip("https://pasteindex.com/gate/xxxx"))
    """

    def __init__(
        self,
        impersonate: str = "chrome131",
        wait_override: Optional[int] = None,
        max_wait: int = 10,
        timeout: int = 20,
    ) -> None:
        self._wait_override = wait_override
        self._max_wait = max_wait
        self._timeout = timeout
        self._session = _cf.Session(impersonate=impersonate)

    def skip(self, gate_url: str) -> str:
        """
        Raises
        ------
        GateError
            Token missing or server returned an error.
        curl_cffi.requests.HTTPError
            Gate page returned 4xx / 5xx.
        """
        resp = self._session.get(gate_url, timeout=self._timeout)
        resp.raise_for_status()

        token = self._extract_token(resp.text, gate_url)
        rctoken = self._extract_rctoken(resp.text)
        headers = {
            "Referer": gate_url,
            "Origin": "https://pasteindex.com",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        d1 = self._post_reveal(token, rctoken, "start", headers)
        if d1.get("enc"):
            return xor_decrypt(d1["enc"], token)

        time.sleep(self._resolve_wait(d1))

        d2 = self._post_reveal(token, rctoken, "reveal", headers)
        if not d2.get("ok") or not d2.get("enc"):
            raise GateError(f"reveal step 2 failed: {d2.get('error', d2)}")
        return xor_decrypt(d2["enc"], token)

    def _extract_token(self, html: str, url: str) -> str:
        m = re.search(r'var _token\s*=\s*"([^"]+)"', html)
        if not m:
            raise GateError(f"_token not found (invalid or expired): {url}")
        return m.group(1)

    def _extract_rctoken(self, html: str) -> str:
        m = re.search(r'id="cf-chl-widget[^"]*"[^>]*value="([^"]+)"', html)
        return m.group(1) if m else ""

    def _post_reveal(self, token: str, rctoken: str, step: str, headers: dict) -> dict:
        r = self._session.post(
            _REVEAL_URL,
            data={"token": token, "rctoken": rctoken, "step": step},
            headers=headers,
            timeout=self._timeout,
        )
        d = r.json()
        if step == "start" and not d.get("ok"):
            raise GateError(f"reveal start failed: {d.get('error', d)}")
        return d

    def _resolve_wait(self, data: dict) -> int:
        if self._wait_override is not None:
            return self._wait_override
        return min(max(int(data.get("wait", 3)), 1), self._max_wait)
