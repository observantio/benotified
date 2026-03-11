"""
Json-related custom types and helper functions.

Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, TypeAlias, TypeGuard
from typing_extensions import TypeAliasType

JSONScalar: TypeAlias = str | int | float | bool | None
if TYPE_CHECKING:
    JSONValue: TypeAlias = JSONScalar | Mapping[str, "JSONValue"] | Sequence["JSONValue"]
else:
    JSONValue = TypeAliasType(
        "JSONValue",
        JSONScalar | Mapping[str, "JSONValue"] | Sequence["JSONValue"],
    )
JSONDict: TypeAlias = dict[str, JSONValue]
JSONList: TypeAlias = list[JSONValue]


def is_json_value(value: object) -> TypeGuard[JSONValue]:
    if value is None or isinstance(value, (str, int, float, bool)):
        return True
    if isinstance(value, Mapping):
        return all(isinstance(key, str) and is_json_value(item) for key, item in value.items())
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return all(is_json_value(item) for item in value)
    return False


def is_json_object(value: object) -> TypeGuard[JSONDict]:
    return isinstance(value, dict) and all(
        isinstance(key, str) and is_json_value(item) for key, item in value.items()
    )


__all__ = ["JSONScalar", "JSONValue", "JSONDict", "JSONList", "is_json_value", "is_json_object"]
