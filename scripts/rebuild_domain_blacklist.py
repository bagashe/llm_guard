#!/usr/bin/env python3
"""Rebuild config/domain_blacklist.txt from public threat feeds."""

from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse
from urllib.request import Request, urlopen


USER_AGENT = "llm_guard-blacklist-rebuilder/1.0"


@dataclass(frozen=True)
class Source:
    name: str
    url: str
    kind: str


SOURCES: tuple[Source, ...] = (
    Source("openphish.feed", "https://openphish.com/feed.txt", "url_lines"),
    Source("urlhaus.csv_recent", "https://urlhaus.abuse.ch/downloads/csv_recent/", "urlhaus_csv"),
    Source("threatfox.csv_recent", "https://threatfox.abuse.ch/export/csv/recent/", "threatfox_csv"),
    Source(
        "phishing_database.active_domains",
        "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
        "domain_lines",
    ),
    Source(
        "nocoin.hosts",
        "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt",
        "hosts_file",
    ),
)


def fetch_text(url: str, timeout: int) -> str:
    req = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(req, timeout=timeout) as response:
        charset = response.headers.get_content_charset() or "utf-8"
        return response.read().decode(charset, errors="replace")


def normalize_host(value: str) -> str:
    v = value.strip().lower().strip("[]").rstrip(".")
    if not v:
        return ""

    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        pass

    if v.startswith("www."):
        v = v[4:]
    if not is_plausible_domain(v):
        return ""
    return v


def is_plausible_domain(value: str) -> bool:
    if " " in value or "." not in value:
        return False
    parts = value.split(".")
    if len(parts) < 2:
        return False
    for part in parts:
        if not part:
            return False
        if part[0] == "-" or part[-1] == "-":
            return False
        for ch in part:
            if not ("a" <= ch <= "z" or "0" <= ch <= "9" or ch == "-"):
                return False
    return True


def host_from_url(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme not in {"http", "https"}:
        return ""
    return normalize_host(parsed.hostname or "")


def parse_domain_lines(text: str) -> Iterable[str]:
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "#" in line:
            line = line.split("#", 1)[0].strip()
        host = normalize_host(line)
        if host:
            yield host


def parse_url_lines(text: str) -> Iterable[str]:
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        host = host_from_url(line)
        if host:
            yield host


def parse_hosts_file(text: str) -> Iterable[str]:
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "#" in line:
            line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        candidate = parts[-1] if parts else ""
        host = normalize_host(candidate)
        if host:
            yield host


def parse_urlhaus_csv(text: str) -> Iterable[str]:
    rows = [line for line in text.splitlines() if line and not line.startswith("#")]
    if not rows:
        return
    reader = csv.reader(io.StringIO("\n".join(rows)))
    for row in reader:
        if len(row) < 3:
            continue
        host = host_from_url(row[2])
        if host:
            yield host


def parse_threatfox_csv(text: str) -> Iterable[str]:
    rows = [line for line in text.splitlines() if line and not line.startswith("#")]
    if not rows:
        return

    def clean(value: str) -> str:
        return value.strip().strip('"').strip()

    reader = csv.reader(io.StringIO("\n".join(rows)))
    for row in reader:
        if len(row) < 4:
            continue
        ioc = clean(row[2])
        ioc_type = clean(row[3]).lower()
        if not ioc:
            continue
        if ioc_type == "url":
            host = host_from_url(ioc)
        elif ioc_type in {"domain", "hostname"}:
            host = normalize_host(ioc)
        elif ioc_type in {"ip:port", "ip"}:
            host = normalize_host(ioc.split(":", 1)[0])
        else:
            host = ""
        if host:
            yield host


def parse_source(source: Source, text: str) -> list[str]:
    if source.kind == "domain_lines":
        return list(parse_domain_lines(text))
    if source.kind == "url_lines":
        return list(parse_url_lines(text))
    if source.kind == "hosts_file":
        return list(parse_hosts_file(text))
    if source.kind == "urlhaus_csv":
        return list(parse_urlhaus_csv(text))
    if source.kind == "threatfox_csv":
        return list(parse_threatfox_csv(text))
    raise ValueError(f"unsupported source kind: {source.kind}")


def build_blacklist(timeout: int) -> tuple[list[str], list[str]]:
    all_hosts: set[str] = set()
    stats: list[str] = []

    for source in SOURCES:
        text = fetch_text(source.url, timeout=timeout)
        parsed_hosts = parse_source(source, text)
        unique_hosts = set(parsed_hosts)
        all_hosts.update(unique_hosts)
        stats.append(
            f"- {source.name}: parsed={len(parsed_hosts)} unique={len(unique_hosts)} url={source.url}"
        )

    return sorted(all_hosts), stats


def write_blacklist(path: Path, hosts: list[str], stats: list[str]) -> None:
    generated = datetime.now(UTC).replace(microsecond=0).isoformat()
    header = [
        "# Host blacklist for tool-call URL restrictions.",
        "# Format: one domain or IP per line. Lines starting with \"#\" are comments.",
        f"# Generated: {generated}",
        "# Sources:",
        *[f"# {line}" for line in stats],
        "",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        f.write("\n".join(header))
        for host in hosts:
            f.write(host + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Rebuild config/domain_blacklist.txt from public feeds")
    parser.add_argument("--out", default="config/domain_blacklist.txt", help="Output file path")
    parser.add_argument("--timeout", type=int, default=30, help="HTTP timeout in seconds")
    args = parser.parse_args()

    try:
        hosts, stats = build_blacklist(timeout=args.timeout)
        write_blacklist(Path(args.out), hosts, stats)
    except Exception as exc:  # noqa: BLE001
        print(f"rebuild failed: {exc}", file=sys.stderr)
        return 1

    print(f"wrote {len(hosts)} hosts to {args.out}")
    for line in stats:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
