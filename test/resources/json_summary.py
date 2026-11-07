"""Summarise a `flutter test --file-reporter json:FILE` report for Robot."""
import json


def summarize(path):
    names, result = {}, {"passed": 0, "failed": 0, "skipped": 0, "names": []}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line.startswith("{"):
                continue
            e = json.loads(line)
            if e.get("type") == "testStart":
                names[e["test"]["id"]] = e["test"]["name"]
            elif e.get("type") == "testDone" and not e.get("hidden"):
                name = names.get(e["testID"], "?")
                if name.startswith("loading "):
                    continue
                if e.get("skipped"):
                    result["skipped"] += 1
                elif e.get("result") == "success":
                    result["passed"] += 1
                else:
                    result["failed"] += 1
                result["names"].append(name)
    return result
