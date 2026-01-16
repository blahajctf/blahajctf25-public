#!/usr/bin/python3.13

def recompile(bytecode):
    co = compile('()', '<string>', 'eval')
    code = co.replace(co_code=bytecode, co_consts=())
    return code

def safe_eval(s):
    return eval(s, {"__builtins__": {}})

try:
    s = bytes.fromhex(input("> "))
    assert s.decode().isprintable()
    assert safe_eval(recompile(s)) == safe_eval(s)
    print("blahaj{REDACTED}")
except Exception:
    exit(0)