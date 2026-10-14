from pathlib import Path
from collections import Counter, defaultdict
from difflib import SequenceMatcher
from datetime import datetime
import re
import csv
import sys

PROJECT = Path(r"D:\SKALBEL SANTE\Desktop\TOUFIK\BN100_PART3_WORKSPACE")
SOURCE = Path(r"D:\SKALBEL SANTE\Desktop\TOUFIK\BN100_ANPP\structure\partie3")
OUT = PROJECT / "audit"

FINDINGS = []
DOCUMENTS = []
CONTENTS = {}

MODEL_PATTERNS = {
    "BN-100 LUX": r"\bBN\s*[-–]?\s*100\s*LUX\b",
    "BN-100A": r"\bBN\s*[-–]?\s*100\s*A\b",
    "BN-100": r"\bBN\s*[-–]?\s*100\b(?!\s*LUX\b|\s*A\b)",
    "BB-100": r"\bBB\s*[-–]?\s*100\b",
    "BB-200": r"\bBB\s*[-–]?\s*200\b",
    "BB-300": r"\bBB\s*[-–]?\s*300\b",
}

STANDARDS = [
    "IEC 60601-1",
    "IEC 60601-1-2",
    "IEC 60601-1-8",
    "IEC 60601-2-21",
    "ISO 14971",
    "ISO 13485",
    "ISO/TR 24971",
    "CISPR 11",
]

SPEC_PATTERNS = {
    "Voltage": r"(?i)(?:220\s*(?:±|\\pm|\+/-)?\s*22?\s*V|rated voltage)",
    "Frequency": r"(?i)(?:50\s*(?:±|\\pm|\+/-)?\s*1\s*Hz|frequency)",
    "Power": r"(?i)(?:800\s*W|1000\s*VA|rated power|maximum input power)",
    "Temperature": r"(?i)(?:32\s*[-–]\s*38\s*°?\s*C|39\s*°?\s*C|40\s*°?\s*C)",
    "Mechanical load": r"(?i)(?:100\s*N|20\s*N|2\s*kg)",
    "Service life": r"(?i)(?:8\s*years?|25[,.]?000\s*h(?:ours?)?)",
}

ARTIFACT_PATTERNS = {
    "OAICITE_ARTIFACT": r"contentReference\s*\[\s*oaicite",
    "MARKDOWN_FENCE": r"(?m)^\s*```",
    "TODO_MARKER": r"(?i)\b(?:TODO|FIXME)\b",
}


def add_finding(severity, code, message, file="", line="", evidence=""):
    FINDINGS.append({
        "severity": severity,
        "code": code,
        "message": message,
        "file": str(file),
        "line": line,
        "evidence": str(evidence).replace("\n", " ")[:500],
    })


def read_source(path):
    for encoding in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            return path.read_text(encoding=encoding), encoding, ""
        except UnicodeDecodeError:
            continue
        except OSError as exc:
            return "", "", str(exc)
    return "", "", "Unable to decode file"


def line_number(text, offset):
    return text.count("\n", 0, offset) + 1


def normalize_paragraph(text):
    text = re.sub(r"(?m)%.*$", " ", text)
    text = text.lower()
    text = re.sub(r"\\[a-zA-Z@]+\*?(?:\[[^\]]*\])?", " ", text)
    text = re.sub(r"[{}$\\]", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def inspect_file(path):
    text, encoding, error = read_source(path)

    if error:
        add_finding("HIGH", "FILE_READ_ERROR", error, path)
        return

    if not text.strip():
        add_finding(
            "MEDIUM", "EMPTY_FILE",
            "File contains no readable text.", path
        )
        return

    CONTENTS[path] = text

    headings = []
    heading_pattern = (
        r"(?m)^\s*\\(?:section|subsection|subsubsection|paragraph)"
        r"\*?\s*(?:\[[^\]]*\])?\s*\{([^}]*)\}"
    )

    for match in re.finditer(heading_pattern, text):
        headings.append(
            f"L{line_number(text, match.start())}: {match.group(1).strip()}"
        )

    DOCUMENTS.append({
        "file": str(path),
        "bytes": path.stat().st_size,
        "encoding": encoding,
        "lines": text.count("\n") + 1,
        "headings": " | ".join(headings),
    })

    for code, pattern in ARTIFACT_PATTERNS.items():
        for match in re.finditer(pattern, text):
            add_finding(
                "HIGH" if code == "OAICITE_ARTIFACT" else "MEDIUM",
                code,
                "Potential source artefact detected.",
                path,
                line_number(text, match.start()),
                match.group(0),
            )

    for model, pattern in MODEL_PATTERNS.items():
        for match in re.finditer(pattern, text, re.IGNORECASE):
            add_finding(
                "INFO", "MODEL_MENTION",
                f"Model identifier mentioned: {model}. Context requires review.",
                path, line_number(text, match.start()), match.group(0)
            )

    for name, pattern in SPEC_PATTERNS.items():
        for match in re.finditer(pattern, text):
            add_finding(
                "INFO", "SPEC_OCCURRENCE",
                f"Potential {name} value. Compare against source documents.",
                path, line_number(text, match.start()), match.group(0)
            )

    for standard in STANDARDS:
        pattern = re.escape(standard).replace(r"\ ", r"\s*")
        for match in re.finditer(pattern, text, re.IGNORECASE):
            add_finding(
                "INFO", "STANDARD_OCCURRENCE",
                f"Standard mentioned: {standard}.",
                path, line_number(text, match.start()), match.group(0)
            )

    # Exact repeated paragraphs within the same file.
    seen = {}
    for block_index, block in enumerate(re.split(r"\n\s*\n", text), 1):
        cleaned = normalize_paragraph(block)
        if len(cleaned) < 120:
            continue

        if cleaned in seen:
            add_finding(
                "MEDIUM", "DUPLICATE_PARAGRAPH",
                f"Repeated normalized paragraph; earlier block {seen[cleaned]}.",
                path, "", block.strip()[:250]
            )
        else:
            seen[cleaned] = block_index


def inspect_cross_file_duplicates():
    paragraphs = []

    for path, text in CONTENTS.items():
        for block in re.split(r"\n\s*\n", text):
            cleaned = normalize_paragraph(block)
            if len(cleaned) >= 150:
                paragraphs.append((path, block.strip(), cleaned))

    # Exact duplicates across files.
    groups = defaultdict(list)
    for path, original, cleaned in paragraphs:
        groups[cleaned].append((path, original))

    for entries in groups.values():
        paths = sorted({str(item[0]) for item in entries})
        if len(paths) > 1:
            add_finding(
                "MEDIUM", "CROSS_FILE_DUPLICATE",
                "Identical normalized paragraph appears in multiple files.",
                " | ".join(paths), "", entries[0][1][:250]
            )

    # Bounded near-duplicate check to keep runtime manageable.
    sample = paragraphs[:400]

    for i, (path_a, text_a, norm_a) in enumerate(sample):
        for path_b, text_b, norm_b in sample[i + 1:]:
            if path_a == path_b:
                continue
            if abs(len(norm_a) - len(norm_b)) > 60:
                continue
            if min(len(norm_a), len(norm_b)) < 180:
                continue

            ratio = SequenceMatcher(
                None, norm_a, norm_b, autojunk=False
            ).ratio()

            if ratio >= 0.94 and norm_a != norm_b:
                add_finding(
                    "LOW", "NEAR_DUPLICATE_PARAGRAPH",
                    f"Possible near-duplicate; similarity={ratio:.3f}.",
                    f"{path_a} | {path_b}", "",
                    f"A: {text_a[:100]} || B: {text_b[:100]}"
                )


def write_reports():
    OUT.mkdir(parents=True, exist_ok=True)

    findings_file = OUT / "findings.csv"
    inventory_file = OUT / "file_inventory.csv"
    standards_file = OUT / "standards_matrix.csv"
    report_file = OUT / "audit_report.md"

    finding_fields = [
        "severity", "code", "message", "file", "line", "evidence"
    ]

    with findings_file.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=finding_fields)
        writer.writeheader()
        writer.writerows(FINDINGS)

    with inventory_file.open("w", newline="", encoding="utf-8-sig") as f:
        fields = ["file", "bytes", "encoding", "lines", "headings"]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(DOCUMENTS)

    with standards_file.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["standard", "files_found"])

        for standard in STANDARDS:
            found = [
                str(path.relative_to(SOURCE))
                for path, text in CONTENTS.items()
                if re.search(re.escape(standard), text, re.IGNORECASE)
            ]
            writer.writerow([standard, " | ".join(found)])

    counts = Counter(item["severity"] for item in FINDINGS)
    code_counts = Counter(item["code"] for item in FINDINGS)

    lines = [
        "# BN-100 LUX Part III Audit Report",
        "",
        f"Generated: {datetime.now().isoformat(timespec='seconds')}",
        f"Source directory: `{SOURCE}`",
        f"Readable TeX files: {len(CONTENTS)}",
        f"Total findings: {len(FINDINGS)}",
        "",
        "## Severity summary",
        "",
    ]

    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        lines.append(f"- {level}: {counts.get(level, 0)}")

    lines.extend(["", "## Finding categories", ""])
    for code, count in code_counts.most_common():
        lines.append(f"- {code}: {count}")

    lines.extend([
        "",
        "## Limitations",
        "",
        "- This is an automated screening report, not regulatory approval.",
        "- A model mention is not automatically an error.",
        "- A repeated paragraph is not automatically unnecessary.",
        "- Technical conflicts require checking authoritative source documents.",
        "- Original LaTeX files are not modified.",
        "",
        "## Findings",
        "",
    ])

    priority = {
        "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4
    }

    for item in sorted(
        FINDINGS,
        key=lambda x: (
            priority.get(x["severity"], 9), x["file"], str(x["line"])
        )
    ):
        lines.append(
            f"### [{item['severity']}] {item['code']}: {item['message']}"
        )
        if item["file"]:
            lines.append(f"- File: `{item['file']}`")
        if item["line"]:
            lines.append(f"- Line: {item['line']}")
        if item["evidence"]:
            lines.append(f"- Evidence: `{item['evidence']}`")
        lines.append("")

    report_file.write_text("\n".join(lines), encoding="utf-8")

    print("\n=== BN-100 LUX PART III AUDIT ===")
    print(f"Files read: {len(CONTENTS)}")
    print(f"Findings:   {len(FINDINGS)}")
    print(f"Report:     {report_file}")
    print(f"Findings:   {findings_file}")
    print(f"Inventory:  {inventory_file}")
    print(f"Standards:  {standards_file}")
    print("Severity counts:", dict(counts))


def main():
    if not SOURCE.exists():
        print(f"ERROR: Source directory not found:\n{SOURCE}")
        sys.exit(2)

    files = sorted(SOURCE.rglob("*.tex"))

    if not files:
        print(f"ERROR: No .tex files found in:\n{SOURCE}")
        sys.exit(3)

    print(f"Found {len(files)} TeX files.")

    for index, path in enumerate(files, start=1):
        inspect_file(path)
        if index % 25 == 0:
            print(f"Scanned {index}/{len(files)} files...")

    inspect_cross_file_duplicates()
    write_reports()


if __name__ == "__main__":
    main()
