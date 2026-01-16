document.addEventListener('DOMContentLoaded', () => {
  const textInput = document.getElementById('text');
  const sendBtn = document.getElementById('send');
  const resultPre = document.getElementById('result');
  const pingBtn = document.getElementById('ping');
  const pongPre = document.getElementById('pong');
  const genKeyBtn = document.getElementById('genkey');

  sendBtn.addEventListener('click', async () => {
    const text = textInput.value || '';
    const path = `/api/check/${encodeURIComponent(text)}`;
    resultPre.textContent = 'Validating';
    try {
      const res = await fetch(path, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' }
      });
      const data = await res.json();
      resultPre.textContent = JSON.stringify(data, null, 2);
    } catch (err) {
      resultPre.textContent = 'Error: ' + err.message;
    }
  });

  pingBtn.addEventListener('click', async () => {
    pongPre.textContent = 'Pinging...';
    try {
      const res = await fetch('/api/ping');
      const data = await res.json();
      pongPre.textContent = JSON.stringify(data, null, 2);
    } catch (err) {
      pongPre.textContent = 'Error: ' + err.message;
    }
  });

  genKeyBtn.addEventListener('click', async () => {
    const keyResultPre = document.getElementById('keyresult');
    keyResultPre.textContent = 'Generating...';
    try {
      const res = await fetch('/api/generate_key');
      const data = await res.json();
      keyResultPre.textContent = JSON.stringify(data, null, 2);
    } catch (err) {
      keyResultPre.textContent = 'Error: ' + err.message;
    }

  });
});
