import json
from datetime import datetime

ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
TIMELINE_FILE = "results/timeline.json"
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
    if not candidates:
        return None
    return max(candidates, key=parse_time)

def main():
    detections = load_detections()
    timeline = load_timeline()

    print(f"{'Event':<10} {'Detect->Triage':>15} {'Triage->Contain':>16} {'Total MTTR':>12}")
    for eid in sorted(timeline.keys()):
        triaged = parse_time(timeline[eid]["triaged"])
        contained = parse_time(timeline[eid]["contained"])
        detected_ts = closest_detection_before(detections, triaged)
        if detected_ts is None:
            print(f"{eid}: no matching detection found before triage time")
            continue
        detected = parse_time(detected_ts)

        d_to_t = (triaged - detected).total_seconds()
        t_to_c = (contained - triaged).total_seconds()
        total = (contained - detected).total_seconds()

        print(f"{eid:<10} {d_to_t:>14.0f}s {t_to_c:>15.0f}s {total:>11.0f}s")

if __name__ == "__main__":
    main()