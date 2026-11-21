import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from transport import Clock, Deadline, Response


class Timer:
    def __init__(self, seconds=900):
        self.tick = 0.0
        self.clock = Clock(lambda: self.tick, self.sleep, lambda: 1795276800 + self.tick)
        self.deadline = Deadline(self.clock, seconds)

    def sleep(self, delta):
        self.tick += delta


def response(value, *, status=200, url="https://data.example/"):
    return Response(status, json.dumps(value).encode(), {}, url)
