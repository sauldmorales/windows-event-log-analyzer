from __future__ import annotations
import argparse
import json
from pathlib import Path
import xml.etree.ElementTree as ET
from datetime import datetime, timezone


TARGET_EVENT_IDS = {4625, 4624, 4672}


def parse_windows_security_xml(xml_path: Path) -> list[dict]:
    """
    Parse Windows Event Viewer exported XML (Security log).
    Extract a small subset of fields for specific Event IDs.
    """
    events: list[dict] = []
    tree = ET.parse(xml_path)
    root = tree.getroot()

    # Exported XML can have different namespaces; handle by searching tag suffix.
    def tag_endswith(elem, suffix: str) -> bool:
        return elem.tag.endswith(suffix)

    for event in root.iter():
        if not tag_endswith(event, "Event"):
            continue

        system = None
        event_data = None
        for child in list(event):
            if tag_endswith(child, "System"):
                system = child
            elif tag_endswith(child, "EventData"):
                event_data = child

        if system is None:
            continue

        event_id = None
        time_created = None

        for s in list(system):
            if tag_endswith(s, "EventID"):
                try:
                    event_id = int((s.text or "").strip())
                except ValueError:
                    event_id = None
            elif tag_endswith(s, "TimeCreated"):
                time_created = s.attrib.get("SystemTime")

        if event_id is None or event_id not in TARGET_EVENT_IDS:
            continue

        fields = {}
        if event_data is not None:
            for d in list(event_data):
                if tag_endswith(d, "Data"):
                    name = d.attrib.get("Name", "Unknown")
                    fields[name] = (d.text or "").strip()

        events.append(
            {
                "event_id": event_id,
                "time_utc": time_created,
                "fields": fields,
            }
        )

    return events


def summarize(events: list[dict]) -> dict:
    counts = {}
    for e in events:
        counts[e["event_id"]] = counts.get(e["event_id"], 0) + 1

    return {
        "total_events": len(events),
        "by_event_id": counts,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Windows Security XML log analyzer (v0.1)")
    ap.add_argument("--infile", required=True, help="Path to exported Security log XML")
    ap.add_argument("--outjson", default="reports/report.json", help="Output JSON path")
    args = ap.parse_args()

    infile = Path(args.infile).expanduser()
    outjson = Path(args.outjson).expanduser()
    outjson.parent.mkdir(parents=True, exist_ok=True)

    events = parse_windows_security_xml(infile)
    report = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "input_file": str(infile),
        "summary": summarize(events),
        "events": events[:200],  # cap output for now
    }

    outjson.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"OK: wrote {outjson} | total_events={report['summary']['total_events']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
