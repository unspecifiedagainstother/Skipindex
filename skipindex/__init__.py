from .skipper import PasteIndexSkipper
from .exceptions import GateError


def skip(gate_url: str, **kwargs) -> str:
    """
    One-shot bypass. All kwargs forwarded to :class:`PasteIndexSkipper`.

        skippaste.skip(url)
        skippaste.skip(url, impersonate="chrome120", timeout=30)
    """
    return PasteIndexSkipper(**kwargs).skip(gate_url)


__all__ = ["skip", "PasteIndexSkipper", "GateError"]
__version__ = "0.1.0"
