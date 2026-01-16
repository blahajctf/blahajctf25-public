from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from binascii import unhexlify
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


HOST_NAME = '0.0.0.0'  
PORT_NUMBER = 8000       
TARGET_PATH = '/submit_race'

KEY = b"7e4a74e57804789c156bd044a04a83c1" 
IV = b"18fa0c8c03699155"                

mapping = {
    'orange': 'Jovial Merryment',
    'blue': 'blahaj{4Rm5_80DY_L3g5_fl35h_5K1N_80N3_51N3w_g00d_LuCk}',
    'yellow': 'Lightning Strikes Thrice',
    'brown': 'Door Knob',
    'white': 'Superstitional Realism',
    'pink': 'Comely Material Morning',
    'red': 'Resolute Mind Afternoon',
    'grey': 'Downtown Skybox'
}

class RaceSubmitHandler(BaseHTTPRequestHandler):

    def _send_response(self, status_code, content_type, body_str):
        """Helper function to send a response with Content-Length."""
        try:
            encoded_body = body_str.encode('utf-8') 
            content_length = len(encoded_body)

            self.send_response(status_code)
            self.send_header('Content-type', content_type)
            self.send_header('Content-Length', str(content_length)) 
            self.end_headers()
            self.wfile.write(encoded_body)
        except Exception:
            try:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Internal Server Error during response generation")
            except:
                 pass 

    def do_GET(self):
        if self.path == "/healthz":
            self._send_response(200, 'text/plain', 'OK')
        else:
            self._send_response(404, 'text/plain', 'Not Found')

    def do_POST(self):
        """Handles POST requests."""
        
        if self.path != TARGET_PATH:
            self._send_response(404, 'text/plain', 'Not Found')
            return
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                 raise ValueError("Content-Length is missing or zero")
            hex_post_data = self.rfile.read(content_length).decode('utf-8')
            ciphertext = unhexlify(hex_post_data)
            cipher = AES.new(KEY, AES.MODE_CBC, IV)
            decrypted_padded = cipher.decrypt(ciphertext)
            decrypted_data = unpad(decrypted_padded, AES.block_size)
            json_string = decrypted_data.decode('utf-8')
            data_dict = json.loads(json_string)
            value_a = "unknown horse"
            if data_dict['a'] in mapping.keys():
                value_a = mapping[data_dict['a']]         
            response_body = str(value_a) 
            self._send_response(200, 'text/plain', response_body)
        except Exception as e:
            print(e)
            self._send_response(400, 'text/plain', 'Bad Request')



if __name__ == '__main__':
    server_address = (HOST_NAME, PORT_NUMBER)
    httpd = HTTPServer(server_address, RaceSubmitHandler)
    print(f"Server starting on http://{HOST_NAME}:{PORT_NUMBER}...") 
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServer shutting down...")
        httpd.server_close()