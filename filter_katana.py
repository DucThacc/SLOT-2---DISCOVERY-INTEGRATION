#!/usr/bin/env python3

from __future__ import annotations

import argparse
import re
from pathlib import Path
from urllib.parse import urlsplit


DEFAULT_BASE_URL = "http://192.168.144.155:3000"
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Filter Katana output by keeping same-origin URLs, stripping the base URL, "
            "deduplicating, and dropping CSS resources."
        )
    )
    parser.add_argument("-i", "--input", default="katana.txt", help="Input Katana file")
    parser.add_argument("-o", "--output", default="katana.filtered.txt", help="Output file")
    parser.add_argument(
        "-b",
        "--base-url",
        default=DEFAULT_BASE_URL,
        help="Base URL to keep and strip from matched URLs",
    )
    return parser.parse_args()


def is_css_url(url: str) -> bool:
    parsed = urlsplit(url)
    return parsed.path.lower().endswith(".css")


def normalize_url(url: str, base_url: str) -> str | None:
    if not url.startswith(base_url):
        return None

    if is_css_url(url):
        return None

    remainder = url[len(base_url) :]
    if not remainder:
        return "/"

    return remainder


def main() -> int:
    args = parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)
    base_url = args.base_url.rstrip("/")

    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    seen: set[str] = set()
    results: list[str] = []

    for line in input_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue

        for match in URL_PATTERN.finditer(line):
            url = match.group(0).strip()
            normalized = normalize_url(url, base_url)
            if normalized is None:
                continue

            if normalized not in seen:
                seen.add(normalized)
                results.append(normalized)

    output_path.write_text("\n".join(results) + ("\n" if results else ""), encoding="utf-8")
    print(f"Filtered {len(results)} entries to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())