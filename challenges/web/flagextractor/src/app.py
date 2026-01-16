# Flag path is /[random_string].txt 

from time import time
import subprocess
import os
import random
import requests
from flask import Flask, render_template_string, render_template, request, send_file

randomKey = random.randint(1000, 10000)

app = Flask(__name__)

def parse_exif_file(filepath, random_id, current_time):
    result = subprocess.run(['exiftool', filepath], capture_output=True)
    if result.returncode != 0:
        subprocess.run(['rm', '-rf', filepath])
        return render_template('upload.html', result='Error processing file')
    result = result.stdout.decode()
    print(result)

    if '{' in result or '}' in result:
        log_filename = f'incident_{random_id}.html'
        log_path = os.path.join('/tmp/logs', log_filename)
        
        os.makedirs('/tmp/logs', exist_ok=True)
        subprocess.run(['cp', filepath, log_path])
        
        subprocess.run(['rm', '-rf', filepath])
        return render_template('upload.html', result=f'Security Incident Detected at {current_time}! Logs of your malicious action has been generated and saved.')
    
    else:

        subprocess.run(['rm', '-rf', filepath])
        return render_template('upload.html', result=f'File processed at {current_time}. Metadata: {result}')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/fetch', methods=['POST'])
def fetch_url():
    link = request.form.get('url')
    
    current_time = int(time())
    random.seed(current_time + randomKey)
    random_id = str(random.randint(1, 1000000000))

    filepath = f'/tmp/{random_id}'

    if not link:
        return render_template('upload.html', result='No URL provided')
    try:
        r = requests.get(link)
        with open(filepath, 'wb') as f:
            f.write(r.content)
            print(f'Fetched content {r.content} from URL and saved to', filepath)
        return parse_exif_file(filepath, random_id, current_time)
    
    except Exception as e:
        return render_template('upload.html', result=f'Error fetching URL: {e}')

@app.route('/logs/<path:filename>')
def view_log(filename):
    clean_result = ''

    if request.remote_addr != '127.0.0.1':
        return "Access Denied", 403
    if not os.path.exists(os.path.join('/tmp/logs', filename)):
        return "Log not found", 404
    
    with open(os.path.join('/tmp/logs', filename), 'r') as f:
        content = f.read()
        blacklist_char = ['_', '.', '[', ']', "'", '"','/']
        clean_result = ''.join([c for c in content if c not in blacklist_char])
        f.close()

    template_str = f"{{% autoescape false %}}{clean_result}{{% endautoescape %}}"
    
    try:
        return render_template_string(template_str)
    except Exception as e:
        print(f"Error rendering log: {e}")
        return f"Error rendering log", 500

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files.get('file')
    if not file:
        return render_template('upload.html', result='No file uploaded')
    
    current_time = int(time())
    random.seed(current_time + randomKey)
    random_id = str(random.randint(1, 1000000000))

    filepath = f'/tmp/{random_id}'
    file.save(filepath)

    return parse_exif_file(filepath, random_id, current_time)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1337)
