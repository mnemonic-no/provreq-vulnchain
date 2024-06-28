"""utility function for iterating over the data dir"""

import json
import os
from typing import Iterator


def cve_files(datadir: str) -> Iterator[dict]:
    """Iterate over the datafiles in a datadir yielding a dict of the content"""

    filenames = []
    for filename in os.listdir(datadir):
        if filename.endswith(".json"):
            filenames.append(os.path.join(datadir, filename))

    for filename in filenames:
        with open(filename, "r", encoding="utf8") as filehandle:
            cve_db = json.load(filehandle)
            if "format" not in cve_db or cve_db["format"] != "NVD_CVE":
                continue
            yield cve_db


def find_metric(cve: dict) -> dict:
    """Find the most recent v3 metric and return it"""

    for metric_str in ["cvssMetricV31", "cvssMetricV30"]:
        if metric_str in cve["metrics"]:
            return cve["metrics"][metric_str]
    return {}
