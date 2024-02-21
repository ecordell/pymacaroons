from typing import Literal, Optional, Self

from .caveat import Caveat
from .serializers.base_serializer import BaseSerializer
from .serializers.binary_serializer import BinarySerializer

MACAROON_V1: int
MACAROON_V2: int

class Macaroon(object):
    def __init__(
        self,
        location: Optional[str | bytes] = None,
        identifier: Optional[str | bytes] = None,
        key: Optional[str | bytes] = None,
        caveats: Optional[list[Caveat]] = None,
        signature: Optional[str | bytes] = None,
        version: int = 1,
    ): ...
    @classmethod
    def deserialize(
        cls, serialized: str | bytes, serializer: BaseSerializer = BinarySerializer()
    ) -> Self: ...
    @property
    def location(self) -> str | None: ...
    @location.setter
    def location(self, string_or_bytes: str | bytes): ...
    @property
    def version(self) -> Literal[1] | Literal[2]: ...
    @property
    def identifier(self) -> str | bytes | None: ...
    @property
    def identifier_bytes(self) -> bytes | None: ...
    @identifier.setter
    def identifier(self, string_or_bytes: str | bytes): ...
    @property
    def signature(self) -> str: ...
    @signature.setter
    def signature(self, string_or_bytes: str | bytes): ...
    @property
    def signature_bytes(self) -> bytes: ...
    def copy(self) -> Self: ...
    def serialize(
        self, serializer: BaseSerializer = BinarySerializer()
    ) -> bytes | str: ...
    def inspect(self) -> str: ...
    def first_party_caveats(self) -> list[Caveat]: ...
    def third_party_caveats(self) -> list[Caveat]: ...
    def prepare_for_request(self, discharge_macaroon: Macaroon) -> Macaroon: ...
    def add_first_party_caveat(self, predicate: str | bytes, **kwargs) -> Self: ...
    def add_third_party_caveat(
        self, location: str | bytes, key: str | bytes, key_id: str | bytes, **kwargs
    ) -> Self: ...
