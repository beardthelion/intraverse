"""Finding persistence: one JSON file per finding plus an index."""

from __future__ import annotations

import json
from pathlib import Path

from .models import Finding


class FindingStore:
    def __init__(self, out_dir: str):
        self.dir = Path(out_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self._findings: dict[str, Finding] = {}

    def add(self, finding: Finding) -> None:
        self._findings[finding.id] = finding
        (self.dir / f"{finding.id}.json").write_text(finding.to_json())
        self._write_index()

    def get(self, finding_id: str) -> Finding | None:
        if finding_id in self._findings:
            return self._findings[finding_id]
        p = self.dir / f"{finding_id}.json"
        return self._load(p) if p.exists() else None

    def _load(self, p: Path) -> Finding:
        from .models import EvidenceItem, SourceLocation, ValidationStatus
        d = json.loads(p.read_text())
        d["evidence"] = [EvidenceItem.from_dict(e) for e in d.get("evidence", [])]
        d["source_locations"] = [SourceLocation.from_dict(l) for l in d.get("source_locations", [])]
        d["validation_status"] = ValidationStatus(d["validation_status"])
        d["vuln_class"] = d.pop("class")
        return Finding(**d)

    def all(self) -> list[Finding]:
        for p in self.dir.glob("*.json"):
            if p.name == "index.json":
                continue
            fid = p.stem
            if fid not in self._findings:
                self._findings[fid] = self._load(p)
        return list(self._findings.values())

    def _write_index(self) -> None:
        idx = [
            {
                "id": f.id,
                "title": f.title,
                "class": f.vuln_class,
                "severity": f.severity,
                "confidence": f.confidence,
                "validation_status": f.validation_status.value,
            }
            for f in self._findings.values()
        ]
        (self.dir / "index.json").write_text(json.dumps(idx, indent=2))
