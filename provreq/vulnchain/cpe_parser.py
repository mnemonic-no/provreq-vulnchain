"""parse and create valid CPE strings"""
import json

map_cpe_index = {
    "cpe_version": 1,
    "part": 2,
    "vendor": 3,
    "product": 4,
    "version": 5,
    "update": 6,
    "edition": 7,
    "language": 8,
    "sw_edition": 9,
    "target_sw": 10,
    "target_hw": 11,
    "other": 12,
}

FORMATTED_STRING = "FORMATTED_STRING"
URI = "URI"
JSON = "JSON"

FORMATS = [FORMATTED_STRING, URI, JSON]


def safe_index(items: list, idx: int) -> str:
    """get empty string if indexing outside list"""

    try:
        return items[idx]
    except IndexError:
        return ""


class CPE:
    """parse and produce valid cpe strings, creating individual
    elements as properties on the object"""

    def __init__(self, cpe_string):
        self._cpe_string = cpe_string
        self._cpe_elements = cpe_string.split(":")
        self._format = FORMATTED_STRING
        self._dict = {}

        for key, value in map_cpe_index.items():
            cpe_value = safe_index(self._cpe_elements, value)
            self._dict[key] = cpe_value
            setattr(self, key, cpe_value)

    @property
    def format(self):
        """Getter for the _format value"""

        return self._format

    @format.setter
    def format(self, value):
        """Setter for the _format value"""

        if value not in FORMATS:
            raise ValueError(f"Format must be one of {FORMATS}")
        self._format = value

    @property
    def dict(self):
        """Getter for the _dict value"""

        return self._dict

    def __repr__(self):
        return str(self)

    def __str__(self):
        if self._format == URI:
            raise NotImplementedError("URI formatting is not yet implemented")
        if self._format == FORMATTED_STRING:
            return "cpe:" + ":".join(getattr(self, key) for key in map_cpe_index)
        if self._format == JSON:
            return json.dumps(self._dict)
        raise ValueError(f"Format must be one of {FORMATS}")
