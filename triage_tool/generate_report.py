import json
from datetime import datetime

ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
TIMELINE_FILE = "results/timeline.json"
REPORT_FILE = "results/mttr_report.md"
RULE_ID = "100010"

def load_detections():
    detections = []
    with open(ALERTS_FILE) as f:
        for line in f:
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue
            if alert.get("rule", {}).get("id") == RULE_ID:
                detections.append(alert["timestamp"])
    return detections

def load_timeline():
    events = {}
    with open(TIMELINE_FILE) as f:
        for line in f:
            entry = json.loads(line)
            eid = entry["event_id"]
            events.setdefault(eid, {})[entry["phase"]] = entry["timestamp"]
    return events

def parse_time(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))

def closest_detection_before(detections, triaged_time):
    candidates = [d for d in detections if parse_time(d) <= triaged_time]
    return max(candidates, key=parse_time) if candidates else None

def main():
    detections = load_detections()
    timeline = load_timeline()
    rows = []

    for eid in sorted(timeline.keys()):
        triaged = parse_time(timeline[eid]["triaged"])
        contained = parse_time(timeline[eid]["contained"])
        detected_ts = closest_detection_before(detections, triaged)
        if detected_ts is None:
            continue
        detected = parse_time(detected_ts)
        total = (contained - detected).total_seconds()
        rows.append((eid, total))

    lines = ["| Run | Total MTTR |", "|---|---|"]
    for eid, total in rows:
        lines.append(f"| {eid} | {total:.0f}s |")

    if len(rows) >= 2:
        first, last = rows[0][1], rows[-1][1]
        pct = ((first - last) / first) * 100
        lines.append(f"\n**Change from first to last run: {pct:.0f}%**")

    report = "\n".join(lines)
    with open(REPORT_FILE, "w") as f:
        f.write(report)
    print(report)

if __name__ == "__main__":
    main()