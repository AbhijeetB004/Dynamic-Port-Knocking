import json
from types import SimpleNamespace

class Config(SimpleNamespace):
    def __init__(self, config_path="config.json"):
        with open(config_path, "r") as f:
            data = json.load(f)
        # Recursively convert dicts to SimpleNamespace for dot-access
        def dict_to_ns(d):
            if isinstance(d, dict):
                return SimpleNamespace(**{k: dict_to_ns(v) for k, v in d.items()})
            elif isinstance(d, list):
                return [dict_to_ns(i) for i in d]
            else:
                return d
        ns = dict_to_ns(data)
        self.__dict__.update(ns.__dict__)