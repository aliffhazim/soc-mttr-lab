import json, sys, datetime, os

LOG_FILE = "results/timeline.json"

def mark(event_id, phase):
    os.makedirs("results", exist_ok=True)
    entry = {
        "event_id": event_id,
        "phase": phase,
        "timestamp": datetime.datetime.now().isoformat()
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"Logged '{phase}' for {event_id} at {entry['timestamp']}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python mark_event.py <event_id> <phase>")
        sys.exit(1)
    mark(sys.argv[1], sys.argv[2])
