"""Shared rev20 embedding prompt-prefix profile."""

from __future__ import annotations

import argparse
from dataclasses import dataclass


MID_QUERY_PREFIX = "observed command line or audit event"
MID_TAG_PREFIX = "behavior tag definition"


@dataclass(frozen=True)
class PromptProfile:
    name: str
    query_prefix: str | None
    tag_prefix: str | None
    description: str


PROMPT_PROFILES: dict[str, PromptProfile] = {
    "mid": PromptProfile(
        name="mid",
        query_prefix=MID_QUERY_PREFIX,
        tag_prefix=MID_TAG_PREFIX,
        description="Default compact semantic prefixes for rev20 behavior retrieval.",
    ),
}


def prompt_profile_names(*, include_none: bool = True) -> list[str]:
    return list(PROMPT_PROFILES)


def add_prompt_profile_argument(
    parser: argparse.ArgumentParser,
    *,
    default: str | None,
    include_none: bool = True,
) -> None:
    parser.add_argument(
        "--prompt-profile",
        choices=prompt_profile_names(include_none=include_none),
        default=default,
        help=(
            "Resolve rev20 query/tag prefixes from a named profile. Explicit --query-prefix/"
            "--tag-prefix override the selected profile."
        ),
    )


def resolve_prompt_prefixes(
    *,
    prompt_profile: str | None,
    query_prefix: str | None,
    tag_prefix: str | None,
    default_profile: str | None,
) -> tuple[str | None, str | None, str | None]:
    profile_name = prompt_profile if prompt_profile is not None else default_profile
    if profile_name is None:
        profile_name = "mid"
    resolved_query = query_prefix
    resolved_tag = tag_prefix
    try:
        profile = PROMPT_PROFILES[profile_name]
    except KeyError as exc:
        raise ValueError(f"unknown rev20 prompt profile: {profile_name}; expected mid") from exc
    if resolved_query is None:
        resolved_query = profile.query_prefix
    if resolved_tag is None:
        resolved_tag = profile.tag_prefix
    return profile_name, resolved_query, resolved_tag


def prompt_profile_metadata(
    *,
    prompt_profile: str | None,
    query_prefix: str | None,
    tag_prefix: str | None,
) -> dict[str, object]:
    profile = PROMPT_PROFILES.get(prompt_profile or "")
    return {
        "prompt_profile": prompt_profile,
        "prompt_profile_experimental": False if profile else None,
        "query_prefix": query_prefix,
        "tag_prefix": tag_prefix,
    }
