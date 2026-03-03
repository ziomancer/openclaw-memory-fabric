#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


H1_RE = re.compile(r"^#\s+(.+?)\s*$")
H2_RE = re.compile(r"^##\s+(.+?)\s*$")
METADATA_LINE_RE = re.compile(r"^(observedat|observed_at|date|timestamp)\s*:\s*(.+)$", re.IGNORECASE)
HEADING_DATE_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:\d{2})?)?)"
)


@dataclass(frozen=True)
class ScriptConfig:
    input_path: Path
    input_root: Path
    output_path: Path
    namespace: str | None
    source_system: str
    source_type: str
    glob_pattern: str
    global_tags: list[str]
    include_preamble: bool
    dry_run: bool


@dataclass(frozen=True)
class FileContext:
    relative_path: str
    file_title: str
    frontmatter: dict[str, Any]
    content: str
    mtime_iso: str


@dataclass(frozen=True)
class Section:
    title: str
    body: str
    header_level: int
    heading_token: str


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        config = ScriptConfig(
            input_path=args.input.resolve(),
            input_root=resolve_input_root(args.input.resolve()),
            output_path=args.output.resolve(),
            namespace=args.namespace,
            source_system=args.source_system,
            source_type=args.source_type,
            glob_pattern=args.glob,
            global_tags=dedupe_tags(args.tag or []),
            include_preamble=args.include_preamble,
            dry_run=args.dry_run,
        )
        files = discover_markdown_files(config.input_path, config.glob_pattern)
        records, file_count, skipped = build_records(config, files)
        if not records:
            raise ValueError("no shared-memory records were emitted from the provided input")
        if not config.dry_run:
            write_ndjson(config.output_path, records)
        destination = str(config.output_path)
        suffix = " (dry run)" if config.dry_run else ""
        print(
            f"Scanned {file_count} files, emitted {len(records)} records, "
            f"skipped {skipped} records, output {destination}{suffix}"
        )
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Convert transcription markdown into NDJSON for openclaw shared-memory import."
    )
    parser.add_argument("input", type=Path, help="Input markdown file or directory")
    parser.add_argument("-o", "--output", type=Path, required=True, help="Output NDJSON file path")
    parser.add_argument("--namespace", help="Optional shared-memory namespace")
    parser.add_argument(
        "--source-system",
        default="transcription_markdown",
        help="sourceSystem for emitted records",
    )
    parser.add_argument(
        "--source-type",
        default="transcript_section",
        help="sourceType for emitted records",
    )
    parser.add_argument(
        "--glob",
        default="**/*.md",
        help="Glob used when the input is a directory (default: **/*.md)",
    )
    parser.add_argument(
        "--tag",
        action="append",
        help="Global tag to append to every emitted record; may be repeated",
    )
    parser.add_argument(
        "--include-preamble",
        action="store_true",
        help="Emit non-empty content before the first H2 heading as its own record",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse input and report counts without writing output",
    )
    return parser


def resolve_input_root(input_path: Path) -> Path:
    return input_path.parent if input_path.is_file() else input_path


def discover_markdown_files(input_path: Path, glob_pattern: str) -> list[Path]:
    if not input_path.exists():
        raise FileNotFoundError(f"input path does not exist: {input_path}")
    if input_path.is_file():
        return [input_path]
    files = sorted(path for path in input_path.glob(glob_pattern) if path.is_file())
    if not files:
        raise FileNotFoundError(f"no markdown files matched {glob_pattern!r} under {input_path}")
    return files


def build_records(config: ScriptConfig, files: list[Path]) -> tuple[list[dict[str, Any]], int, int]:
    records: list[dict[str, Any]] = []
    skipped = 0
    for file_path in files:
        file_context = load_file_context(file_path, config.input_root)
        file_records, file_skipped = build_records_for_file(file_context, config)
        records.extend(file_records)
        skipped += file_skipped
    return records, len(files), skipped


def load_file_context(file_path: Path, input_root: Path) -> FileContext:
    raw = file_path.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
    frontmatter, body = extract_frontmatter(raw)
    frontmatter = sanitize_frontmatter(frontmatter)
    file_title, content = extract_file_title(frontmatter, body, file_path.stem)
    stat = file_path.stat()
    return FileContext(
        relative_path=file_path.relative_to(input_root).as_posix(),
        file_title=file_title,
        frontmatter=frontmatter,
        content=content,
        mtime_iso=format_datetime_utc(datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)),
    )


def extract_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    match = re.match(r"\A---\n(.*?)\n---(?:\n|$)", text, flags=re.DOTALL)
    if not match:
        if text.startswith("---\n"):
            raise ValueError("frontmatter starts with --- but has no closing --- line")
        return {}, text
    raw_frontmatter = match.group(1)
    remainder = text[match.end() :]
    frontmatter = parse_simple_yaml(raw_frontmatter)
    if not isinstance(frontmatter, dict):
        raise ValueError("frontmatter must be a mapping")
    return frontmatter, remainder


def parse_simple_yaml(text: str) -> dict[str, Any]:
    lines = text.splitlines()
    parsed_lines: list[tuple[int, str]] = []
    for line_number, raw_line in enumerate(lines, start=1):
        if "\t" in raw_line:
            raise ValueError(f"frontmatter line {line_number}: tabs are not supported")
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        parsed_lines.append((indent, raw_line[indent:]))
    if not parsed_lines:
        return {}
    node, index = parse_yaml_block(parsed_lines, 0, parsed_lines[0][0])
    if index != len(parsed_lines):
        raise ValueError("frontmatter parsing did not consume all lines")
    if not isinstance(node, dict):
        raise ValueError("frontmatter root must be a mapping")
    return node


def parse_yaml_block(
    lines: list[tuple[int, str]],
    start: int,
    indent: int,
) -> tuple[Any, int]:
    if start >= len(lines):
        return {}, start
    if lines[start][1].startswith("- "):
        return parse_yaml_list(lines, start, indent)
    return parse_yaml_map(lines, start, indent)


def parse_yaml_map(lines: list[tuple[int, str]], start: int, indent: int) -> tuple[dict[str, Any], int]:
    result: dict[str, Any] = {}
    index = start
    while index < len(lines):
        line_indent, content = lines[index]
        if line_indent < indent:
            break
        if line_indent != indent:
            raise ValueError(f"frontmatter line has unexpected indentation: {content!r}")
        if content.startswith("- "):
            break
        key, separator, remainder = content.partition(":")
        if not separator or not key.strip():
            raise ValueError(f"invalid frontmatter mapping entry: {content!r}")
        key = key.strip()
        remainder = remainder.strip()
        index += 1
        if remainder in {"|", ">"}:
            raise ValueError(f"unsupported frontmatter block scalar for key {key!r}")
        if remainder:
            result[key] = parse_yaml_scalar(remainder)
            continue
        next_index = index
        if next_index < len(lines) and lines[next_index][0] > indent:
            value, index = parse_yaml_block(lines, next_index, lines[next_index][0])
            result[key] = value
        else:
            result[key] = None
    return result, index


def parse_yaml_list(lines: list[tuple[int, str]], start: int, indent: int) -> tuple[list[Any], int]:
    result: list[Any] = []
    index = start
    while index < len(lines):
        line_indent, content = lines[index]
        if line_indent < indent:
            break
        if line_indent != indent:
            raise ValueError(f"frontmatter line has unexpected indentation: {content!r}")
        if not content.startswith("- "):
            break
        remainder = content[2:].strip()
        index += 1
        if remainder in {"|", ">"}:
            raise ValueError("unsupported frontmatter list block scalar")
        if remainder:
            result.append(parse_yaml_scalar(remainder))
            continue
        if index < len(lines) and lines[index][0] > indent:
            value, index = parse_yaml_block(lines, index, lines[index][0])
            result.append(value)
        else:
            result.append(None)
    return result, index


def parse_yaml_scalar(value: str) -> Any:
    lowered = value.lower()
    if lowered in {"null", "~"}:
        return None
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if value.startswith(("'", '"')):
        try:
            return ast.literal_eval(value)
        except (SyntaxError, ValueError) as exc:
            raise ValueError(f"invalid quoted scalar {value!r}") from exc
    if value.startswith("[") and value.endswith("]"):
        return parse_inline_list(value[1:-1])
    if value.startswith("{") and value.endswith("}"):
        return parse_inline_map(value[1:-1])
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    if re.fullmatch(r"-?\d+\.\d+", value):
        return float(value)
    return value


def parse_inline_list(text: str) -> list[Any]:
    if not text.strip():
        return []
    return [parse_yaml_scalar(part.strip()) for part in split_inline_items(text)]


def parse_inline_map(text: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if not text.strip():
        return result
    for item in split_inline_items(text):
        key, separator, value = item.partition(":")
        if not separator or not key.strip():
            raise ValueError(f"invalid inline mapping entry: {item!r}")
        result[key.strip()] = parse_yaml_scalar(value.strip())
    return result


def split_inline_items(text: str) -> list[str]:
    items: list[str] = []
    current: list[str] = []
    quote: str | None = None
    depth = 0
    for char in text:
        if quote:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
            current.append(char)
            continue
        if char in "[{":
            depth += 1
            current.append(char)
            continue
        if char in "]}":
            depth = max(0, depth - 1)
            current.append(char)
            continue
        if char == "," and depth == 0:
            items.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    if current:
        items.append("".join(current).strip())
    return [item for item in items if item]


def sanitize_frontmatter(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return [sanitize_frontmatter(item) for item in value]
    if isinstance(value, dict):
        return {str(key): sanitize_frontmatter(item) for key, item in value.items()}
    raise ValueError(f"unsupported frontmatter value type: {type(value).__name__}")


def extract_file_title(
    frontmatter: dict[str, Any],
    body: str,
    fallback_title: str,
) -> tuple[str, str]:
    frontmatter_title = frontmatter.get("title")
    stripped_body = body
    detected_title: str | None = None
    lines = body.splitlines()
    first_non_empty = 0
    while first_non_empty < len(lines) and not lines[first_non_empty].strip():
        first_non_empty += 1
    if first_non_empty < len(lines):
        match = H1_RE.match(lines[first_non_empty].strip())
        if match:
            detected_title = normalize_heading_text(match.group(1))
            next_line = first_non_empty + 1
            while next_line < len(lines) and not lines[next_line].strip():
                next_line += 1
            stripped_body = "\n".join(lines[next_line:])
    if not detected_title:
        for line in lines:
            match = H1_RE.match(line.strip())
            if match:
                detected_title = normalize_heading_text(match.group(1))
                break
    file_title = normalize_heading_text(str(frontmatter_title).strip()) if frontmatter_title else None
    if not file_title:
        file_title = detected_title or fallback_title
    return file_title, stripped_body.strip()


def build_records_for_file(file_context: FileContext, config: ScriptConfig) -> tuple[list[dict[str, Any]], int]:
    sections, preamble = split_sections(file_context.content)
    skipped = 0
    records: list[dict[str, Any]] = []
    title_counts: dict[str, int] = {}
    shared_tags = merge_tags(config.global_tags, normalize_frontmatter_tags(file_context.frontmatter.get("tags")))
    section_index = 0

    if sections:
        if config.include_preamble and preamble.strip():
            preamble_section = Section(
                title=f"{file_context.file_title} Preamble",
                body=preamble.strip(),
                header_level=0,
                heading_token="preamble",
            )
            record = build_record(
                file_context,
                preamble_section,
                section_index,
                shared_tags,
                config,
                title_counts,
            )
            if record:
                records.append(record)
                section_index += 1
            else:
                skipped += 1
        for section in sections:
            record = build_record(
                file_context,
                section,
                section_index,
                shared_tags,
                config,
                title_counts,
            )
            if record:
                records.append(record)
                section_index += 1
            else:
                skipped += 1
        return records, skipped

    if not file_context.content.strip():
        return [], 1
    fallback_section = Section(
        title=file_context.file_title,
        body=file_context.content.strip(),
        header_level=1,
        heading_token=file_context.file_title,
    )
    record = build_record(
        file_context,
        fallback_section,
        section_index,
        shared_tags,
        config,
        title_counts,
    )
    if record:
        return [record], 0
    return [], 1


def split_sections(content: str) -> tuple[list[Section], str]:
    if not content.strip():
        return [], ""
    lines = content.splitlines()
    sections: list[Section] = []
    preamble_lines: list[str] = []
    current_title: str | None = None
    current_lines: list[str] = []

    for raw_line in lines:
        match = H2_RE.match(raw_line.strip())
        if match:
            if current_title is not None:
                sections.append(
                    Section(
                        title=normalize_heading_text(current_title),
                        body="\n".join(current_lines).strip(),
                        header_level=2,
                        heading_token=normalize_heading_text(current_title),
                    )
                )
            else:
                preamble_lines = current_lines[:]
            current_title = match.group(1)
            current_lines = []
            continue
        current_lines.append(raw_line)

    if current_title is not None:
        sections.append(
            Section(
                title=normalize_heading_text(current_title),
                body="\n".join(current_lines).strip(),
                header_level=2,
                heading_token=normalize_heading_text(current_title),
            )
        )
        return sections, "\n".join(preamble_lines).strip()

    return [], content.strip()


def build_record(
    file_context: FileContext,
    section: Section,
    section_index: int,
    tags: list[str],
    config: ScriptConfig,
    title_counts: dict[str, int],
) -> dict[str, Any] | None:
    body = section.body.strip()
    if not body:
        return None
    title = normalize_heading_text(section.title) or file_context.file_title
    slug_base = slugify(section.heading_token or title or "document")
    occurrence = title_counts.get(slug_base, 0) + 1
    title_counts[slug_base] = occurrence
    source_item_id = build_source_item_id(file_context.relative_path, slug_base, occurrence)
    observed_at = resolve_observed_at(body, title, file_context)
    metadata = {
        "relativePath": file_context.relative_path,
        "fileTitle": file_context.file_title,
        "heading": title,
        "headingPath": [title],
        "sectionIndex": section_index,
        "headerLevel": section.header_level,
        "frontmatter": file_context.frontmatter,
    }
    record: dict[str, Any] = {
        "sourceSystem": config.source_system,
        "sourceType": config.source_type,
        "sourceItemId": source_item_id,
        "observedAt": observed_at,
        "title": title,
        "text": f"{title}\n\n{body}".strip(),
        "metadata": metadata,
    }
    if config.namespace:
        record["namespace"] = config.namespace
    if tags:
        record["tags"] = tags
    return record


def normalize_heading_text(text: str) -> str:
    cleaned = text.strip()
    cleaned = re.sub(r"\s+#+\s*$", "", cleaned)
    return cleaned.strip()


def slugify(text: str) -> str:
    slug = text.strip().lower()
    slug = re.sub(r"\s+", "-", slug)
    slug = re.sub(r"[^a-z0-9._-]+", "-", slug)
    slug = re.sub(r"-{2,}", "-", slug)
    slug = slug.strip("-._")
    return slug or "document"


def build_source_item_id(relative_path: str, slug_base: str, occurrence: int) -> str:
    suffix = f":{occurrence}" if occurrence > 1 else ""
    return f"{relative_path}#h2:{slug_base}{suffix}"


def normalize_frontmatter_tags(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    raise ValueError("frontmatter tags must be a string or list")


def merge_tags(first: list[str], second: list[str]) -> list[str]:
    return dedupe_tags([*first, *second])


def dedupe_tags(tags: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for raw_tag in tags:
        tag = str(raw_tag).strip()
        if not tag or tag in seen:
            continue
        seen.add(tag)
        result.append(tag)
    return result


def resolve_observed_at(body: str, heading: str, file_context: FileContext) -> str:
    for candidate in iter_section_metadata_candidates(body):
        parsed = parse_timestamp(candidate)
        if parsed:
            return parsed
    heading_match = HEADING_DATE_RE.search(heading)
    if heading_match:
        parsed = parse_timestamp(heading_match.group(1))
        if parsed:
            return parsed
    for key in ("observed_at", "observedAt", "date", "timestamp"):
        value = file_context.frontmatter.get(key)
        if value is None:
            continue
        parsed = parse_timestamp(str(value))
        if parsed:
            return parsed
    parsed_mtime = parse_timestamp(file_context.mtime_iso)
    if parsed_mtime:
        return parsed_mtime
    return format_datetime_utc(datetime.now(timezone.utc))


def iter_section_metadata_candidates(body: str) -> list[str]:
    candidates: list[str] = []
    non_empty_seen = 0
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        non_empty_seen += 1
        if non_empty_seen > 8:
            break
        match = METADATA_LINE_RE.match(stripped)
        if match:
            candidates.append(match.group(2).strip())
    return candidates


def parse_timestamp(value: str) -> str | None:
    raw = value.strip()
    if not raw:
        return None
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
        dt = datetime.strptime(raw, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return format_datetime_utc(dt)
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
            return format_datetime_utc(dt)
        except ValueError:
            pass
    normalized = raw.replace("z", "Z")
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return format_datetime_utc(dt)


def format_datetime_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def write_ndjson(output_path: Path, records: list[dict[str, Any]]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
            handle.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())
