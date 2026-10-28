"""Strict classifier response schema, separate from authoritative analysis records."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Classification(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    label: Literal["repeat_to_tool", "benign", "uncertain"]
    score: float = Field(ge=0, le=1, allow_inf_nan=False)
    source_ids: tuple[str, ...]
    reason: str = Field(max_length=512)

    @classmethod
    def parse(cls, text: str, source_ids: frozenset[str]) -> "Classification":
        result = cls.model_validate_json(text)
        if not set(result.source_ids).issubset(source_ids):
            raise ValueError("ram:unknown_source")
        return result
