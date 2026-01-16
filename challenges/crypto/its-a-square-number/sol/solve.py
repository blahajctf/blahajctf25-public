import requests
from sympy.ntheory.factor_ import factorint
from sympy.ntheory.residue_ntheory import sqrt_mod
from sympy.ntheory.modular import crt

import re

url = "http://172.17.0.2:1337"
s = requests.Session()
r = s.get(url)

expr = re.compile('<div class=square>(.*)</div>')
result, n = [*map(int, re.findall(expr, r.text))]

p, q = factorint(n).keys()
pairs = [(result % p, p), (result % q, q)]

solutions = []
for pair in pairs:
    value, modulus = pair
    root = sqrt_mod(value, modulus)
    solutions.append(root)

ans = crt([p, q], solutions)[0]
r = s.post(url, data={'answer':ans})
expr = re.compile('blahaj{.*}')
print(re.findall(expr, r.text)[0])
