"""
mark_event.py

The "stopwatch" script. Run this manually the moment you take a real
action, right when you triage an alert, and again right when you
contain it. It doesn't calculate anything, it just records exactly
when something happened.

Usage:
    python3 mark_event.py <event_id> <phase>

Example:
    python3 mark_event.py hydra01 triaged
    python3 mark_event.py hydra01 contained
"""

import json, sys, datetime, os

LOG_FILE = "results/timeline.json"

def mark(event_id, phase):
    """Append one timestamped entry to the timeline log."""
    os.makedirs("results", exist_ok=True)

    entry = {
        "event_id": event_id,
        "phase": phase,
        # UTC, not local time, so this lines up cleanly with Wazuh's
        # own alert timestamps (which are also UTC). Mixing timezones
        # here was an actual bug earlier in this project.
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

    # Append-only log: one JSON object per line, never overwritten.
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")

    print(f"Logged '{phase}' for {event_id} at {entry['timestamp']}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python mark_event.py <event_id> <phase>")
        sys.exit(1)
    mark(sys.argv[1], sys.argv[2])
