from pathlib import Path
from src.wevtx_analyzer import parse_windows_security_xml

def test_parser_no_crash_on_empty_sample(tmp_path: Path):
    p = tmp_path / "empty.xml"
    p.write_text("<Events></Events>", encoding="utf-8")
    events = parse_windows_security_xml(p)
    assert isinstance(events, list)
    assert len(events) == 0
