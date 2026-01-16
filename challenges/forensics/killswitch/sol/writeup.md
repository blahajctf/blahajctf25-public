```py
import os, socket
from urllib.request import urlopen

data = bytearray(urlopen("http://192.168.76.1:9000/flag.txt").read())
keys = [socket.gethostname().encode(), os.getcwd().encode(), open("/secret/key", "rb").read().strip()]
print(data, keys)
for k in keys:
    if k:
        for i in range(len(data)): data[i] ^= k[i % len(k)]

open("flag.enc", "w").write(data.hex())
```

heres ur get_flag.py just decrypt the nonsense

