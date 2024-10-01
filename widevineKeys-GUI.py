import tkinter as tk
from tkinter import scrolledtext
from pywidevine.device import Device
from pywidevine.pssh import PSSH
from pywidevine.cdm import Cdm
import urllib.parse
import requests
import base64
import codecs
import re

wv_device = 'Device.wvd'


def parse_curl(curl_command):
    url_match = re.search(r"curl\s+'(.*?)'", curl_command)
    url = url_match.group(1) if url_match else ""

    method_match = re.search(r"-X\s+(\w+)", curl_command)
    method = method_match.group(1) if method_match else "UNDEFINED"

    headers = {}
    headers_matches = re.findall(r"-H\s+'([^:]+):\s*(.*?)'", curl_command)
    for header in headers_matches:
        headers[header[0]] = header[1]

    data_match = re.search(r"--data(?:-raw)?\s+(?:(\$?')|(\$?{?))(.*?)'", curl_command, re.DOTALL)
    if data_match:
        raw_prefix = data_match.group(1)
        data = data_match.group(3)
        if raw_prefix and raw_prefix.startswith('$'):
            data = None
        else:
            data = data.replace('\\\\', '\\').replace('\\x', '\\\\x')
            try:
                data = codecs.decode(data, 'unicode_escape')
            except Exception as e:
                print(f"Error decoding data: {e}")
                data = ""
    else:
        data = ""

    return url, method, headers, data


def widevine(pssh_, wv_device, url, headers, data):
    pssh = PSSH(pssh_)
    device = Device.load(wv_device)
    cdm = Cdm.from_device(device)
    session_id = cdm.open()
    challenge = cdm.get_license_challenge(session_id, pssh)

    if data:
        if match := re.search(r'"(CAQ=.*?)"', data): 
            challenge = data.replace(match.group(1), base64.b64encode(challenge).decode())
        elif match := re.search(r'"(CAES.*?)"', data):
            challenge = data.replace(match.group(1), base64.b64encode(challenge).decode())
        elif match := re.search(r'=(CAES.*?)(&.*)?$', data): 
            b64challenge = base64.b64encode(challenge).decode()
            quoted = urllib.parse.quote_plus(b64challenge)
            challenge = data.replace(match.group(1), quoted)
        elif match := re.search(r'\[[^\]]*\]', str(data)):
            challenge = data.replace(match.group(0), str(list(challenge)))

    payload = challenge if data is None else challenge

    response = requests.post(url, headers=headers, data=payload)
    if not response.ok:
        cdm.close(session_id)
        return f'failed to get license: {response}\n{response.content}'
    license_message = response.content
    try:
        match = re.search(r'"(CAIS.*?)"', response.content.decode('utf-8'))
        if match:
            license_message = base64.b64decode(match.group(1))
    except:
        pass


    cdm.parse_license(session_id, license_message)
    keys = []
    for key in cdm.get_keys(session_id):
        if key.type != 'SIGNING':
            keys.append(f"--key {key.kid.hex}:{key.key.hex()}")
    cdm.close(session_id)
    return "\n".join(keys)

def execute():
    curl_command = curl_input.get("1.0", tk.END).strip()
    pssh_ = pssh_input.get("1.0", tk.END).strip()

    # قم بتحليل curl
    url, method, headers, data = parse_curl(curl_command)
    
    # نفذ دالة widevine
    result = widevine(pssh_, wv_device, url, headers, data)
    
    # عرض النتيجة في الحقل المخصص
    result_output.delete("1.0", tk.END)
    result_output.insert(tk.END, result)

root = tk.Tk()
root.title("Widevine L3 GUI v2")
root.geometry("850x700")  

def right_click_popup(event):
    try:
        right_click_menu.tk_popup(event.x_root, event.y_root)
    finally:
        right_click_menu.grab_release()

right_click_menu = tk.Menu(root, tearoff=0)
right_click_menu.add_command(label="Cut", command=lambda: root.focus_get().event_generate("<<Cut>>"))
right_click_menu.add_command(label="Copy", command=lambda: root.focus_get().event_generate("<<Copy>>"))
right_click_menu.add_command(label="Paste", command=lambda: root.focus_get().event_generate("<<Paste>>"))
root.bind("<Button-3>", right_click_popup)

label_font = ("Arial", 12, "bold")
input_font = ("Arial", 11)
button_font = ("Arial", 12, "bold")

pssh_label = tk.Label(root, text="PSSH:", font=label_font, fg="#333333")
pssh_label.pack(pady=(20, 5))

pssh_input = scrolledtext.ScrolledText(root, width=100, height=2, font=input_font, bd=2, relief="groove")
pssh_input.pack(pady=5)

curl_label = tk.Label(root, text="License cURL(bash):", font=label_font, fg="#333333")
curl_label.pack(pady=(20, 5))

curl_input = scrolledtext.ScrolledText(root, width=100, height=10, font=input_font, bd=2, relief="groove")
curl_input.pack(pady=5)

execute_button = tk.Button(root, text="GET KEYS", font=button_font, bg="#4CAF50", fg="white", width=15, height=2, command=execute)
execute_button.pack(pady=20)

result_label = tk.Label(root, text="", font=label_font, fg="#333333")
result_label.pack(pady=(20, 5))

result_output = scrolledtext.ScrolledText(root, width=100, height=10, font=input_font, bd=2, relief="groove")
result_output.pack(pady=5)

root.mainloop()
