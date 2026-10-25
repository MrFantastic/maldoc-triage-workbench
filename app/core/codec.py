"""JSON encoding for results passed between the GUI and worker processes.

Only allowlisted dataclasses and enums are rebuilt, so a compromised worker
can't make the GUI instantiate arbitrary objects (unlike pickle).
"""
from __future__ import annotations

import base64
import dataclasses
import enum
import json
from typing import Any

_CLASSES: dict[str, type] = {}
_ENUMS: dict[str, type] = {}


def register(*classes: type) -> None:
    """Allow these dataclasses and enums to cross the worker boundary."""
    for cls in classes:
        if isinstance(cls, type) and issubclass(cls, enum.Enum):
            _ENUMS[cls.__name__] = cls
        elif dataclasses.is_dataclass(cls):
            _CLASSES[cls.__name__] = cls
        else:
            raise TypeError(f"{cls!r} is not a dataclass or enum")


def _register_defaults() -> None:
    if _CLASSES:
        return
    from . import models, router
    from ..adapters import container_adapter, macro_adapter, office_adapter, pdfid_adapter
    register(models.Severity, models.Family, models.Finding, models.ToolResult, router.RouteInfo,
             pdfid_adapter.PdfidOptions, pdfid_adapter.KeywordRow, pdfid_adapter.PdfidData,
             office_adapter.Indicator, office_adapter.MacroModule, office_adapter.OfficeTriageData,
             macro_adapter.Module, macro_adapter.AnalysisRow, macro_adapter.MacroData,
             macro_adapter.MacroOptions,
             container_adapter.Part, container_adapter.Relationship, container_adapter.PartsData,
             container_adapter.MetaData)


def encode(obj: Any) -> Any:
    """JSON-safe form of obj: allowlisted dataclasses and enums are tagged, bytes are base64."""
    _register_defaults()
    if isinstance(obj, enum.Enum):
        if type(obj).__name__ not in _ENUMS:
            raise TypeError(f"enum {type(obj).__name__} is not allowlisted")
        return {"__enum__": type(obj).__name__, "v": obj.value}
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        name = type(obj).__name__
        if name not in _CLASSES:
            raise TypeError(f"dataclass {name} is not allowlisted")
        return {"__dc__": name, **{f.name: encode(getattr(obj, f.name)) for f in dataclasses.fields(obj)}}
    if isinstance(obj, (bytes, bytearray)):
        return {"__b64__": base64.b64encode(bytes(obj)).decode("ascii")}
    if isinstance(obj, dict):
        return {str(k): encode(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [encode(v) for v in obj]
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    raise TypeError(f"cannot encode {type(obj).__name__}")


def decode(obj: Any) -> Any:
    """Rebuild objects from encode()'s output; classes that aren't allowlisted are refused."""
    _register_defaults()
    if isinstance(obj, list):
        return [decode(v) for v in obj]
    if not isinstance(obj, dict):
        return obj
    if "__enum__" in obj:
        cls = _ENUMS.get(obj["__enum__"])
        if cls is None:
            raise ValueError(f"enum {obj['__enum__']!r} is not allowlisted")
        return cls(obj["v"])
    if "__dc__" in obj:
        cls = _CLASSES.get(obj["__dc__"])
        if cls is None:
            raise ValueError(f"class {obj['__dc__']!r} is not allowlisted")
        names = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: decode(v) for k, v in obj.items() if k in names})
    if "__b64__" in obj and len(obj) == 1:
        return base64.b64decode(obj["__b64__"])
    return {k: decode(v) for k, v in obj.items()}


def dumps(obj: Any) -> str:
    """encode() and serialize as compact JSON."""
    return json.dumps(encode(obj), separators=(",", ":"))


def loads(text: str | bytes) -> Any:
    """Parse JSON and decode() it."""
    return decode(json.loads(text))
