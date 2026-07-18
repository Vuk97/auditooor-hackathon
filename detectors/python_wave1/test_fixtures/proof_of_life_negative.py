"""fixture: negative — must not trigger proof_of_life."""

import ast
import json


def safe_json(payload):
    return json.loads(payload)


def safe_parse(payload):
    return ast.literal_eval(payload)


def no_eval():
    x = 1 + 2
    return x
