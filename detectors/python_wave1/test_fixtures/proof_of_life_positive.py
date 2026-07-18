"""fixture: positive — should trigger proof_of_life."""


def unsafe_exec(payload):
    # eval() on untrusted input — classic RCE.
    return eval(payload)


def evaluate_rule(rule, ctx):
    # nested eval call is also flagged.
    if ctx:
        return eval(rule)
    return None


def safe_parse(payload):
    # ast.literal_eval is safer — must NOT be flagged by this detector.
    import ast
    return ast.literal_eval(payload)
