import pickle
import subprocess

import yaml


def load_config(path):
    with open(path) as fh:
        return yaml.load(fh)


def run(cmd):
    return subprocess.call(cmd, shell=True)


def restore(blob):
    return pickle.loads(blob)
