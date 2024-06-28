"""Parse CVSS Metrics"""


class CVSSMetric:
    """CVSSMetric represent the name and value of a CVSS Vector element"""

    def __init__(self, metric, metric_map):
        self._metric = metric
        key, val = metric.split(":")

        if key not in metric_map:
            raise ValueError(f"Unknown metric '{key}' found in vector")

        self.key_name = metric_map[key]["name"]
        self.key = key
        if val not in metric_map[key]["map"]:
            raise ValueError(f"Unknown value '{val}' for key '{key}' found in vector")
        self.value_name = metric_map[key]["map"][val]["name"]
        self.value_index = metric_map[key]["map"][val]["index"]
        self.value = val

    def __repr__(self):
        return str(self)

    def __str__(self):
        return f"CVSSMetric({self.key_name}, {self.value_name})"


class CVSSVector:
    """Iterate over components in the CVSSVector"""

    def __init__(self, vec: str, metrics_map: dict) -> None:
        self._curr = -1
        elements = vec.split("/")
        if not elements[0].startswith("CVSS:3"):
            print(elements)
            raise ValueError("Not a valid CVSS v3 vector")

        self._metrics_map = metrics_map

        self._vector = [
            CVSSMetric(element, self._metrics_map) for element in elements[1:]
        ]

        self._version = "3.1"

    @property
    def version(self) -> str:
        """Return the version used"""

        return f"CVSS:{self._version}"

    @property
    def provides(self) -> set:
        """Create a set of all the provides based off the CVSS Vector"""

        prov = set()
        for elem in self._vector:
            prov.update(self._metrics_map[elem.key]["map"][elem.value]["provides"])
        return prov

    @property
    def requires(self) -> set:
        """Create a set of all the provides based off the CVSS Vector"""

        req = set()
        for elem in self._vector:
            req.update(self._metrics_map[elem.key]["map"][elem.value]["requires"])
        return req

    def __iter__(self):
        self._curr = -1
        return self

    def __str__(self):
        return str(self._vector)

    def marshal(self) -> str:
        """Marshal a vector string from the CVSS Vector"""

        return f"{self.version}/" + "/".join(f"{v.key}:{v.value}" for v in self._vector)

    def __next__(self) -> CVSSMetric:
        self._curr += 1
        if self._curr == len(self._vector):
            raise StopIteration
        return self._vector[self._curr]

    def __getitem__(self, key):
        for elem in self._vector:
            if elem.key == key:
                return elem
        raise IndexError(f"{key} not found in {self}")

    def __setitem__(self, key, value):
        for elem in self._vector:
            if elem.key == key:
                elem.value = value
                elem.value_name = self._metrics_map[key]["map"][value]["name"]
                elem.value_index = self._metrics_map[key]["map"][value]["index"]
                break

    def combine(self, newvector):
        """Combine another CVSS vector, creating a new worst case vector"""
        for combined_metric in self:
            new_metric = newvector[combined_metric.key]
            if new_metric.value_index < combined_metric.value_index:
                self[new_metric.key] = new_metric.value
