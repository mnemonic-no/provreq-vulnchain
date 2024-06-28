"""Parse and create provides and requires data structure"""

import argparse
import collections
import json
import os
from typing import Text

from pkg_resources import resource_string

from provreq.vulnchain import cvss_parser, pbar
from provreq.vulnchain.cpe_parser import CPE
from provreq.vulnchain.db import cve_files, find_metric


def levenshtein(a: Text, b: Text) -> int:
    "Calculates the Levenshtein distance between a and b."
    n, m = len(a), len(b)
    if n > m:
        # Make sure n <= m, to use O(min(n,m)) space
        a, b = b, a
        n, m = m, n
    current = list(range(n + 1))
    for i in range(1, m + 1):
        previous, current = current, [i] + [0] * n
        for j in range(1, n + 1):
            add, delete = previous[j] + 1, current[j - 1] + 1
            change = previous[j - 1]
            if a[j - 1] != b[i - 1]:
                change = change + 1
            current[j] = min(add, delete, change)
    return current[n]


def handle_arguments() -> argparse.Namespace:
    """Parse the command line arguments"""

    parser = argparse.ArgumentParser(
        prog="Parse CVE",
        description=(
            "Parse the CVE data and create a new data file" "for use with AEP"
        ),
        epilog="The end",
    )

    parser.add_argument("-d", "--datadir", type=str, help="Where to read the data")
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="agent_promises.json",
        help="Destination of output file",
    )
    parser.add_argument(
        "--description",
        type=str,
        default="promise_descriptions.csv",
        help="Name of the promise description file",
    )
    return parser.parse_args()


escvar: collections.Counter = collections.Counter()


def is_privilege_escalation(cve: dict) -> bool:
    """Check if the description contains some form of privilege escalation text"""
    for desc in cve["descriptions"]:
        if not desc["lang"] == "en":
            continue
        words = desc["value"].split()
        words = [word.lower().strip(',.()"') for word in words]
        for i in range(len(words) - 1):
            text = " ".join(words[i : i + 2])
            if levenshtein(text, "escalate privileges") < 4:
                escvar[text] += 1
                return True
            if levenshtein(text, "privilege escalation") < 4:
                escvar[text] += 1
                return True
    return False


def words_around(cve: dict) -> bool:
    for desc in cve["descriptions"]:
        if not desc["lang"] == "en":
            continue
        words = desc["value"].split()
        for i, word in enumerate(words):
            if " ".join(words[i : i + 2]) == "of privilege":
                escvar[" ".join(words[i - 1 : i + 2])] += 1


def main() -> None:
    """main entry point"""

    metrics_map = json.loads(
        resource_string(__name__, "data/metrics.json").decode("utf-8")
    )
    args = handle_arguments()

    count = 0

    totalfiles = len(os.listdir(args.datadir))
    progress_bar = pbar.ProgressBar("Finding CVE data", totalfiles)

    all_promises = set()

    counter = collections.Counter()

    agent = {}
    for i, cve_db in enumerate(cve_files(args.datadir)):
        for vuln in cve_db["vulnerabilities"]:
            if "cve" not in vuln:
                print("Skipping", vuln)
                continue

            cve = vuln["cve"]

            # is_privilege_escalation(cve)
            words_around(cve)

            metric = find_metric(cve)
            if not metric:
                continue

            req = set()
            prov = set()
            applications = get_applications(cve)

            for metric_element in metric:
                count += 1

                vector = cvss_parser.CVSSVector(
                    metric_element["cvssData"]["vectorString"], metrics_map
                )

                counter[f"{vector['C']}{vector['I']}{vector['A']}"] += 1
                if (
                    vector["C"].value == "N"
                    and vector["I"].value == "N"
                    and vector["A"].value == "N"
                ):
                    with open("cia_all_none_IDS.log", "a") as f:
                        f.write(cve["id"])
                        f.write(f" by {cve['sourceIdentifier']}")
                        f.write("\n")

                req.update(mod_requires(vector.requires, applications))

                scope_changed = vector["S"].value.upper() == "C"
                prov.update(mod_provides(vector.provides, applications, scope_changed))

                all_promises.update(req)
                all_promises.update(prov)

            if "access_local_os" in prov and (
                "privileges_low_os" in prov or "privileges_high_os" in prov
            ):
                prov.add("access_adjacent")

            agent[cve["id"]] = {
                "conditional_provides": {},
                "mitigations": [],
                "name": cve["id"],
                "provides": list(prov),
                "relevant_for": [],
                "requires": list(req),
                "children": {},
                "agent_class": ["unknown"],
            }
        progress_bar.update(i)
    progress_bar.done()

    for n in counter.most_common(30):
        print(n)

    print(f"Parsed a total of {count} valid CVSS v3x vectors")
    print(f"Writing {args.output}")
    with open(args.output, "w", encoding="utf-8") as filehandle:
        json.dump(agent, filehandle, indent="   ", sort_keys=True)
    print(f"Writing {args.description}")
    with open(args.description, "w", encoding="utf-8") as filehandle:
        for promise in all_promises:
            filehandle.write(f"{promise}, lorem ipsum Stultus est populus\n")
    print("Done")
    for w, c in escvar.most_common(50):
        print(w, c)


def mod_provides(provides: set, applications: set, scope_changed: bool) -> set[str]:
    """Modify the list of provides based on wether there are applications
    in the list and the scope changed"""

    new_provides = set()
    if not applications or scope_changed:
        for provide in provides:
            if promise_should_not_be_specified(provide):
                # Exclude where scope change does not make sense
                new_provides.add(provide)
            else:
                if applications:
                    new_provides.add(f"{provide}_os".replace("high", "low"))
                else:
                    new_provides.add(f"{provide}_os")
        return new_provides

    for app in applications:
        for provide in provides:
            if promise_should_not_be_specified(provide):
                # Exclude where scope change does not make sense
                new_provides.add(provide)
            else:
                new_provides.add(f"{provide}_{app}")

    return new_provides


def mod_requires(requires: set, applications: set) -> set[str]:
    """Modify requires based on wether there are applications in the list"""

    new_requires = set()
    if not applications:
        for require in requires:
            if promise_should_not_be_specified(require):
                new_requires.add(require)
            else:
                new_requires.add(f"{require}_os")
        return new_requires
    for app in applications:
        for require in requires:
            if promise_should_not_be_specified(require):
                new_requires.add(require)
            else:
                new_requires.add(f"{require}_{app}")
    return new_requires


def promise_should_not_be_specified(promise: str) -> bool:
    """check wether a promise should be specified with either
    _os or _{application}"""

    if any(x in promise for x in ["adjacent", "physical"]):
        return True
    return False


def get_applications(cve) -> set[str]:
    """Get a list of applications strings in the configurations"""

    res: set[str] = set()
    if "configurations" not in cve:
        return res

    for config in cve["configurations"]:
        for node in config["nodes"]:
            if node["negate"]:
                continue
            for cpe_match in node["cpeMatch"]:
                cpe = CPE(cpe_match["criteria"])
                if cpe.part == "a":  # application
                    res.add(slugify(f"{cpe.vendor}_{cpe.product}"))
    return res


def slugify(inp: str) -> str:
    """Create a safe string"""

    unsafe = "[]\\,()$#+"
    safe = ""
    for char in inp:
        if char in unsafe:
            safe += "_"
        else:
            safe += char
    return safe
