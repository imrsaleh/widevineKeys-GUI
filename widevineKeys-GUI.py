import os, sys
import tkinter as tk
from tkinter import ttk, scrolledtext
from tkinter import *
from pywidevine.device import Device
from pywidevine.cdm import Cdm
from pywidevine.pssh import PSSH
from pywidevine.exceptions import InvalidLicenseMessage
import ast
import base64
from base64 import b64encode
import json
import requests
import re
import glob
import subprocess
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET
from beaupy.spinners import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from httpx import Client

##################Generic Widevine####################################
def execute_script1():
    cdm = None
    try:
        pssh_input = pssh_entry1.get()
        ilicurl = url_entry1.get()
        headers_input = headers_entry1.get("1.0", "end").strip()
        params_input = params_entry1.get("1.0", "end").strip()
        cookies_input = cookies_entry1.get("1.0", "end").strip()

        if not pssh_input or not ilicurl:
            result_box.insert(tk.END, "data must not be empty!\n")
            return

        params = ast.literal_eval(params_input) if params_input else {}
        headers = ast.literal_eval(headers_input) if headers_input else {}
        cookies = ast.literal_eval(cookies_input) if cookies_input else {}
        pssh = PSSH(pssh_input)

        files = glob.glob('Device/*.wvd')
        if not files:
            result_box.insert(tk.END, "Device not found\n")


        device = Device.load(files[0])
        cdm = Cdm.from_device(device)

        session_id = cdm.open()
        challenge = cdm.get_license_challenge(session_id, pssh)

        if params_input and headers_input and cookies_input:
            license = requests.post(ilicurl, params=params, cookies=cookies, headers=headers, data=challenge)
        elif params:
            license = requests.post(ilicurl, params=params, data=challenge)
        elif headers:
            license = requests.post(ilicurl, headers=headers, data=challenge)
        elif cookies:
            license = requests.post(ilicurl, cookies=cookies, data=challenge)
        else:
            license = requests.post(ilicurl, data=challenge)

        license.raise_for_status()

        cdm.parse_license(session_id, license.content)

        # print keys
        with open('KeysDB.txt', 'a') as file:
            file.write('\n')
            for key in cdm.get_keys(session_id):
                if key.type != 'SIGNING':
                   key_info = f"{key.kid.hex}:{key.key.hex()}\n"
                   result_box.insert(tk.END, key_info)
                   file.write(key_info)
            result_box.insert(tk.END, "keys saved in KeysDB.txt\n")

    except InvalidLicenseMessage as e:
        result_box.insert(tk.END, f"Erorr: {str(e)}\n")
    except requests.exceptions.RequestException as e:
        result_box.insert(tk.END, f"Error: {str(e)}\n")
    except requests.exceptions.HTTPError as e:
        result_box.insert(tk.END, f"HTTP Error: {str(e)}\n")
    except Exception as e:
        result_box.insert(tk.END, f"Error: {str(e)}\n")
    finally:
        if cdm is not None:
            cdm.close(session_id)

def execute_download1():
    download_url = download_url_entry1.get()
    video_name = video_name_entry1.get()
    save_direcion = save_direcion_entry1.get()
    if not download_url or not video_name or not save_direcion:
        result_box.insert(tk.END, "Download URL, video name, save location must not be empty!\n")
        return
    command = f'start cmd /k N_m3u8DL-RE.exe "{download_url}" --key-text-file KeysDB.txt --use-shaka-packager --binary-merge --save-dir {save_direcion} --save-name "{video_name}" -mt -M format=mkv:muxer=mkvmerge --no-log'
    subprocess.Popen(command, shell=True)

        
     ######### DRMToday #########
def execute_script2():
    cdm = None
    try:
        pssh_input = pssh_entry2.get()
        ilicurl = url_entry2.get()
        headers_input = headers_entry2.get("1.0", "end").strip()

        if not pssh_input or not ilicurl:
            result_box.insert(tk.END, "data must not be empty!\n")
            return

        headers = ast.literal_eval(headers_input) if headers_input else {}
        pssh = PSSH(pssh_input)

        files = glob.glob('Device/*.wvd')
        if not files:
            result_box.insert(tk.END, "Device not found\n")


        device = Device.load(files[0])
        cdm = Cdm.from_device(device)

        session_id = cdm.open()
        
        challenge = cdm.get_license_challenge(session_id, pssh)

        if headers:
            license = requests.post(ilicurl, data=challenge, headers=headers)
        else:
            license = requests.post(ilicurl, data=challenge)
        
        license.raise_for_status()  
        
        license = license.json()["license"]
        
        cdm.parse_license(session_id, license)

        # print keys
        with open('KeysDB.txt', 'a') as file:
            file.write('\n')
            for key in cdm.get_keys(session_id):
                if key.type != 'SIGNING':
                   key_info = f"{key.kid.hex}:{key.key.hex()}\n"
                   result_box.insert(tk.END, key_info)
                   file.write(key_info)
            result_box.insert(tk.END, "keys saved in KeysDB.txt\n")

    except InvalidLicenseMessage as e:
        result_box.insert(tk.END, f"Erorr: {str(e)}\n")
    except requests.exceptions.RequestException as e:
        result_box.insert(tk.END, f"Error: {str(e)}\n")
    except requests.exceptions.HTTPError as e:
        result_box.insert(tk.END, f"HTTP Error: {str(e)}\n")
    except Exception as e:
        result_box.insert(tk.END, f"Error: {str(e)}\n")
    finally:
        if cdm is not None:
            cdm.close(session_id)

def execute_download2():
    download_url = download_url_entry2.get()
    video_name = video_name_entry2.get()
    save_direcion = save_direcion_entry2.get()
    if not download_url or not video_name or not save_direcion:
        result_box.insert(tk.END, "Download URL, video name, save location must not be empty!\n")
        return
    command = f'start cmd /k N_m3u8DL-RE.exe "{download_url}" --key-text-file KeysDB.txt --use-shaka-packager --binary-merge --save-dir {save_direcion} --save-name "{video_name}" -mt -M format=mkv:muxer=mkvmerge --no-log'
    subprocess.Popen(command, shell=True)

      ########### Widevine b64encode challenge ###########
def execute_script3():
    cdm = None
    try:
        pssh_input = pssh_entry3.get()
        LicenseUrl = url_entry3.get()
        value1 = value1_entry3.get()
        value1value = value1value_entry3.get("1.0", "end").strip()
        value2 = value2_entry3.get()
        value2value = value2value_entry3.get("1.0", "end").strip()
        value3 = value3_entry3.get()
        value3value = value3value_entry3.get("1.0", "end").strip()
        value4 = value4_entry3.get()
        value4value = value4value_entry3.get("1.0", "end").strip()
        value5 = value5_entry3.get()
        params_input = params_entry3.get("1.0", "end").strip()
        headers_input = headers_entry3.get("1.0", "end").strip()
        cookies_input = cookies_entry3.get("1.0", "end").strip()

        if not pssh_input or not LicenseUrl:
            result_box.insert(tk.END, "data must not be empty!\n")
            return
        
        params = ast.literal_eval(params_input) if params_input else {}
        headers = ast.literal_eval(headers_input) if headers_input else {}
        cookies = ast.literal_eval(cookies_input) if cookies_input else {}
        
        pssh = PSSH(pssh_input)

        files = glob.glob('Device/*.wvd')
        if not files:
            result_box.insert(tk.END, "Device not found\n")

        device = Device.load(files[0])
        cdm = Cdm.from_device(device)

        session_id = cdm.open()
        challenge = cdm.get_license_challenge(session_id, pssh)
        request = b64encode(challenge)

        license_data = ({'getRawWidevineLicense':{value1: value1value, value2: value2value, value3: value3value, value4: value4value, value5: str(request, "utf-8")}})


        if params_input and headers_input and cookies_input:
            license = requests.post(LicenseUrl, params=params, cookies=cookies, headers=headers, json=license_data)
        elif params:
            license = requests.post(LicenseUrl, params=params, json=license_data)
        elif headers:
            license = requests.post(LicenseUrl, headers=headers, json=license_data)
        elif cookies:
            license = requests.post(LicenseUrl, cookies=cookies, json=license_data)
        else:
            license = requests.post(LicenseUrl, json=license_data)

        license.raise_for_status()  
        cdm.parse_license(session_id, license.content)

        # print keys
        with open('KeysDB.txt', 'a') as file:
            file.write('\n')
            for key in cdm.get_keys(session_id):
                if key.type != 'SIGNING':
                   key_info = f"{key.kid.hex}:{key.key.hex()}\n"
                   result_box.insert(tk.END, key_info)
                   file.write(key_info)
            result_box.insert(tk.END, "keys saved in KeysDB.txt\n")

    except InvalidLicenseMessage as e:
        result_box.insert(tk.END, f"Erorr: {str(e)}\n")
    except requests.exceptions.RequestException as e:
        result_box.insert(tk.END, f"Error: {str(e)}\n")
    except requests.exceptions.HTTPError as e:
        result_box.insert(tk.END, f"HTTP Error: {str(e)}\n")
    except Exception as e:
        result_box.insert(tk.END, f"Error: {str(e)}\n")
    finally:
        if cdm is not None:
            cdm.close(session_id)

def execute_download3():
    download_url = download_url_entry3.get()
    video_name = video_name_entry3.get()
    save_direcion = save_direcion_entry3.get()
    if not download_url or not video_name or not save_direcion:
        result_box.insert(tk.END, "Download URL, video name, save location must not be empty!\n")
        return
    command = f'start cmd /k N_m3u8DL-RE.exe "{download_url}" --key-text-file KeysDB.txt --use-shaka-packager --binary-merge --save-dir {save_direcion} --save-name "{video_name}" -mt -M format=mkv:muxer=mkvmerge --no-log'
    subprocess.Popen(command, shell=True)

         ############ list(challenge) Payload data ###########
def update_data_name():
    data = payload_entry4.get("1.0", tk.END)
    match = re.search(r'(\w+)"\s*:\s*\[\s*(\d+,\s*)*\d+\s*\]', data, re.DOTALL)
    data_info_entry4.delete(0, tk.END)
    if data.strip():  # check if the field is not empty
        if match:
            value_before_numbers = match.group(1)
            data_info_entry4.insert(0, value_before_numbers)
    window.after(2000, update_data_name)  # re-run the function after 2000 milliseconds

def execute_script4():
    cdm = None
    try:
        pssh_input = pssh_entry4.get()
        LicenseUrl = url_entry4.get()
        payload_input = payload_entry4.get("1.0", tk.END).strip()
        data_info = data_info_entry4.get()
        headers_input = headers_entry4.get("1.0", "end").strip()
        params_input = params_entry4.get("1.0", "end").strip()
        cookies_input = cookies_entry4.get("1.0", "end").strip()

        if not pssh_input or not LicenseUrl or not payload_input or not data_info:
            result_box.insert(tk.END, "data must not be empty!\n")
            return

        params = ast.literal_eval(params_input) if params_input else {}
        headers = ast.literal_eval(headers_input) if headers_input else {}
        cookies = ast.literal_eval(cookies_input) if cookies_input else {}

        def str_to_dict(str_value):
            return json.loads(str_value)
        def dict_to_str(dict_value):
            return json.dumps(dict_value)

        pssh = PSSH(pssh_input)

        files = glob.glob('Device/*.wvd')
        if not files:
            result_box.insert(tk.END, "Device not found\n")

        device = Device.load(files[0])
        cdm = Cdm.from_device(device)

        session_id = cdm.open()
        challenge = cdm.get_license_challenge(session_id, pssh)
        payload = str_to_dict(payload_input)
        payload[data_info] = list(challenge)

        if params_input and headers_input and cookies_input:
            license = requests.post(LicenseUrl, params=params, cookies=cookies, headers=headers, data=dict_to_str(payload))
        elif params:
            license = requests.post(LicenseUrl, params=params, data=dict_to_str(payload))
        elif headers:
            license = requests.post(LicenseUrl, headers=headers, data=dict_to_str(payload))
        elif cookies:
            license = requests.post(LicenseUrl, cookies=cookies, data=dict_to_str(payload))
        else:
            license = requests.post(LicenseUrl, data=dict_to_str(payload))

        license.raise_for_status()  

        cdm.parse_license(session_id, license.content)

        # print keys
        with open('KeysDB.txt', 'a') as file:
            file.write('\n')
            for key in cdm.get_keys(session_id):
                if key.type != 'SIGNING':
                   key_info = f"{key.kid.hex}:{key.key.hex()}\n"
                   result_box.insert(tk.END, key_info)
                   file.write(key_info)
            result_box.insert(tk.END, "keys saved in KeysDB.txt\n")
                   

    except InvalidLicenseMessage as e:
        result_box.insert(tk.END, f"Erorr: {str(e)}\n")
    except requests.exceptions.RequestException as e:
        result_box.insert(tk.END, f"Error: {str(e)}\n")
    except requests.exceptions.HTTPError as e:
        result_box.insert(tk.END, f"HTTP Error: {str(e)}\n")
    except Exception as e:
        result_box.insert(tk.END, f"Error: {str(e)}\n")
    finally:
        if cdm is not None:
            cdm.close(session_id)

def execute_download4():
    download_url = download_url_entry4.get()
    video_name = video_name_entry4.get()
    save_direcion = save_direcion_entry4.get()
    if not download_url or not video_name or not save_direcion:
        result_box.insert(tk.END, "Download URL, video name, save location must not be empty!\n")
        return
    command = f'start cmd /k N_m3u8DL-RE.exe "{download_url}" --key-text-file KeysDB.txt --use-shaka-packager --binary-merge --save-dir {save_direcion} --save-name "{video_name}" -mt -M format=mkv:muxer=mkvmerge --no-log'
    subprocess.Popen(command, shell=True)

################################# channel 4 #################################################
def execute_script5():
    DEFAULT_HEADERS = {
    'Content-type': 'application/json',
    'Accept': '*/*',
    'Referer': 'https://www.channel4.com/',
    "user-agent": "Dalvik/2.1.0 (Linux; U; Android 12; SM-G930F Build/SQ1D.220105.007)"
    }

    MPD_HEADERS = {
        'Content-type': 'application/dash+xml',
        'Accept': '*/*',
        'Referer': 'https://www.channel4.com/',
        "user-agent": "Dalvik/2.1.0 (Linux; U; Android 12; SM-G930F Build/SQ1D.220105.007)"
    }

    global client
    client = Client()

    class ComplexJsonEncoder(json.JSONEncoder):
        def default(self, o):
            if hasattr(o, 'to_json'):
                return o.to_json()
            return json.JSONEncoder.default(self, o)


    class Video:
        def __init__(self, video_type: str, url: str):
            self.video_type = video_type
            self.url = url

        def to_json(self):
            resp = {}

            if self.video_type != "":
                resp['type'] = self.video_type
            if self.url != "":
                resp['url'] = self.url
            return resp


    class DrmToday:
        def __init__(self, request_id: str, token: str, video: Video, message: str):
            self.request_id = request_id
            self.token = token
            self.video = video
            self.message = message

        def to_json(self):
            resp = {}

            if self.request_id != "":
                resp['request_id'] = self.request_id
            if self.token != "":
                resp['token'] = self.token
            if self.video != "":
                resp['video'] = self.video
            if self.message != "":
                resp['message'] = self.message
            return resp


    class Status:
        def __init__(self, success: bool, status_type: str):
            self.success = success
            self.status_type = status_type


    class VodConfig:
        def __init__(self, vodbs_url: str, drm_today: DrmToday, message: str):
            self.vodbs_url = vodbs_url
            self.drm_today = drm_today
            self.message = message


    class VodStream:
        def __init__(self, token: str, uri: str, brand_title: str, episode_title: str):
            self.token = token
            self.uri = uri
            self.brand_title = brand_title
            self.episode_title = episode_title

        def to_json(self):
            resp = {}

            if self.token != "":
                resp['token'] = self.token
            if self.uri != "":
                resp['uri'] = self.uri
            return resp


    class LicenseResponse:
        def __init__(self, license_response: str, status: Status):
            self.license_response = license_response
            self.status = status

        def to_json(self):
            resp = {}

            if self.license_response != "":
                resp['license'] = self.license_response
            if self.status != "":
                resp['status'] = self.status
            return resp


    def decrypt_token(token: str):
        try:
            cipher = AES.new(
                b"\x41\x59\x44\x49\x44\x38\x53\x44\x46\x42\x50\x34\x4d\x38\x44\x48",
                AES.MODE_CBC,
                b"\x31\x44\x43\x44\x30\x33\x38\x33\x44\x4b\x44\x46\x53\x4c\x38\x32"
            )
            decoded_token = base64.b64decode(token)
            decrypted_string = unpad(cipher.decrypt(
                decoded_token), 16, style='pkcs7').decode('UTF-8')
            license_info = decrypted_string.split('|')
            return VodStream(license_info[1], license_info[0], '', '')
        except: 
            print('[!] Failed decrypting VOD stream !!!')
            raise


    def get_vod_stream(asset_id: str):
        try:
            url = f'https://ais.channel4.com/asset/{asset_id}?client=android-mod'
            req = client.get(url)
            
            root = ET.fromstring(req.content)
            asset_info_xpath = './assetInfo/'

            brand_title = root.find(asset_info_xpath + 'brandTitle').text
            brand_title = brand_title.replace(':', ' ').replace('/', ' ')

           
            episode_title = root.find(asset_info_xpath + 'episodeTitle').text
            episode_title = episode_title.replace('/', ' ').replace(':', ' ')

            stream_xpath = f'{asset_info_xpath}videoProfiles/videoProfile[@name=\'widevine-stream-4\']/stream/'
            uri = root.find(stream_xpath + 'uri').text
            token = root.find(stream_xpath + 'token').text
            vod_stream = VodStream(token, uri, brand_title, episode_title)
            return vod_stream
        except: 
            print('[!] Failed getting VOD stream !!!')
            raise


    def get_asset_id(url: str):
        try:
            req = client.get(url)

            init_data = re.search(
                '<script>window\\.__PARAMS__ = (.*)</script>',
                ''.join(
                    req.content.decode()
                    .replace('\u200c', '')
                    .replace('\r\n', '')
                    .replace('undefined', 'null')
                )
            )
            init_data = json.loads(init_data.group(1))
            asset_id = int(init_data['initialData']['selectedEpisode']['assetId'])

            if asset_id == 0:
                raise  
            return asset_id
        except:  
            print('[!] Failed getting asset ID !!!')
            raise


    def get_config():
        try:
            req = client.get(
                'https://static.c4assets.com/all4-player/latest/bundle.app.js')
            #req.raise_for_status
            configs = re.findall(
                "JSON\\.parse\\(\\\'(.*?)\\\'\\)",
                ''.join(
                    req.content.decode()
                    .replace('\u200c', '')
                    .replace('\\"', '\"')
                )
            )
            config = json.loads(configs[1])
            video_type = config['protectionData']['com.widevine.alpha']['drmtoday']['video']['type']
            message = config['protectionData']['com.widevine.alpha']['drmtoday']['message']
            video = Video(video_type, '')
            drm_today = DrmToday('', '', video, message)
            vod_config = VodConfig(config['vodbsUrl'], drm_today, '')
            return vod_config
        except: 
            print('[!] Failed getting production config !!!')
            raise


    def get_service_certificate(url: str, drm_today: DrmToday):
        try:
            req = client.post(url, data=json.dumps(
                drm_today.to_json(), cls=ComplexJsonEncoder), headers=DEFAULT_HEADERS)
            req.raise_for_status
            resp = json.loads(req.content)
            license_response = resp['license']
            status = Status(resp['status']['success'], resp['status']['type'])
            return LicenseResponse(license_response, status)
        except:
            print('[!] Failed getting signed DRM certificate !!!')
            raise


    def get_license_response(url: str, drm_today: DrmToday):
        try:
            req = client.post(url, data=json.dumps(
                drm_today.to_json(), cls=ComplexJsonEncoder), headers=DEFAULT_HEADERS)
            req.raise_for_status
            resp = json.loads(req.content)
            license_response = resp['license']
            status = Status(resp['status']['success'], resp['status']['type'])

            if not status.success:
                raise  
            return LicenseResponse(license_response, status)
        except:  
            print('[!] Failed getting license challenge !!!')
            raise


    def get_kid(url: str):
        try:
            req = client.get(url, headers=MPD_HEADERS)
            #req.raise_for_status
            kid = re.search('cenc:default_KID="(.*)"', req.text).group(1)
            return kid
        except:  
            print('[!] Failed getting KID !!!')
            raise


    def generate_pssh(kid: str):
        try:
            kid = kid.replace('-','')
            s = f'000000387073736800000000edef8ba979d64acea3c827dcd51d21ed000000181210{kid}48e3dc959b06'
            return b64encode(bytes.fromhex(s)).decode()
        except: 
                print('[!] Failed generating PSSH !!!')
                raise



    def main(url ):

        config = get_config()

        spinner = Spinner(DOTS)
        spinner.start()

        asset_id = get_asset_id(url)
        encrypted_vod_stream = get_vod_stream(asset_id)
        # Decrypt the stream token
        decrypted_vod_stream = decrypt_token(encrypted_vod_stream.token)
        # Setup the initial license request
        #mpd
        config.drm_today.video.url = encrypted_vod_stream.uri  # MPD
        # license 'message;
        config.drm_today.token = decrypted_vod_stream.token  # Decrypted Token
        config.drm_today.request_id = asset_id  # Video asset ID
        # Get the SignedDrmCertificate (common privacy cert)
        # sending token lic_url to method
        service_cert = get_service_certificate(
            decrypted_vod_stream.uri, config.drm_today).license_response
        # Load the WVD and generate a session ID
        files = glob.glob('Device/*.wvd')
        if not files:
            result_box.insert(tk.END, "Device not found\n")

        device = Device.load(files[0])
        cdm = Cdm.from_device(device)
        session_id = cdm.open()
        cdm.set_service_certificate(session_id, service_cert)
        kid = get_kid(config.drm_today.video.url)
        # Generate the PSSH
        pssh = generate_pssh(kid)
        challenge = cdm.get_license_challenge(
            session_id, PSSH(pssh), privacy_mode=True)
        config.drm_today.message = base64.b64encode(challenge).decode('UTF-8')
        # Get license response
        license_response = get_license_response(
            decrypted_vod_stream.uri, config.drm_today)
        # Parse license challenge
        cdm.parse_license(session_id, license_response.license_response)
        decryption_key = ''
        # Return keys
        with open('KeysDB.txt', 'a') as file:
            file.write('\n')
            for key in cdm.get_keys(session_id):
                if key.type != 'SIGNING':
                   key_info = f"{key.kid.hex}:{key.key.hex()}\n"
                   result_box.insert(tk.END, key_info)
                   file.write(key_info)
            mpd_link = f"[MPD] {config.drm_today.video.url}\n"
            result_box.insert(tk.END, mpd_link)
            result_box.insert(tk.END, "keys saved in KeysDB.txt\n")
        # Close session, disposes of session data
        cdm.close(session_id)

    if __name__ == "__main__":
        
        url = url_entry5.get()
        if not url:
            result_box.insert(tk.END, "data must not be empty!\n")
            return
        main(url)

    
def execute_download5():
    download_url = download_url_entry5.get()
    video_name = video_name_entry5.get()
    save_direcion = save_direcion_entry5.get()
    if not download_url or not video_name or not save_direcion:
        result_box.insert(tk.END, "Download URL, video name, save location must not be empty!\n")
        return
    command = f'start cmd /k N_m3u8DL-RE.exe "{download_url}" --key-text-file KeysDB.txt --use-shaka-packager --binary-merge --save-dir {save_direcion} --save-name "{video_name}" -mt -M format=mkv:muxer=mkvmerge --no-log'
    subprocess.Popen(command, shell=True)

#############################################################################################

##########right click menu###########
def right_click_popup(event):
    try:
        right_click_menu.tk_popup(event.x_root, event.y_root)
    finally:
        right_click_menu.grab_release()

#############window################
window = tk.Tk()
window.title("Widevine Keys By BigWolf")
window.iconbitmap('logo.ico')

right_click_menu = tk.Menu(window, tearoff=0)
right_click_menu.add_command(label="Cut", command=lambda: window.focus_get().event_generate("<<Cut>>"))
right_click_menu.add_command(label="Copy", command=lambda: window.focus_get().event_generate("<<Copy>>"))
right_click_menu.add_command(label="Paste", command=lambda: window.focus_get().event_generate("<<Paste>>"))
window.bind("<Button-3>", right_click_popup)

window.geometry('950x850')

notebook = ttk.Notebook(window)
notebook.pack(pady=10, expand=True, fill='both')

tab1 = ttk.Frame(notebook)
tab2 = ttk.Frame(notebook)
tab3 = ttk.Frame(notebook)
tab4 = ttk.Frame(notebook)
tab5 = ttk.Frame(notebook)
notebook.add(tab1, text='    Generic            ')
notebook.add(tab2, text='    DRMtoday           ')
notebook.add(tab3, text='   B64encode Challenge ')
notebook.add(tab4, text='    List Challenge     ')
notebook.add(tab5, text='    Channel 4          ')

# TAB 1
ttk.Label(tab1, text="PSSH* :").grid(column=0, row=0, sticky='w', padx=10, pady=5)
pssh_entry1 = ttk.Entry(tab1, font=('Arial', 8), width=130)
pssh_entry1.grid(column=1, row=0, sticky='w', padx=10, pady=5)

ttk.Label(tab1, text="License URL* :").grid(column=0, row=1, sticky='w', padx=10, pady=5)
url_entry1 = ttk.Entry(tab1, font=('Arial', 8), width=130)
url_entry1.grid(column=1, row=1, sticky='w', padx=10, pady=5)

ttk.Label(tab1, text="Headers :").grid(column=0, row=2, sticky='w', padx=10, pady=5)
headers_entry1 = tk.Text(tab1, font=('Arial', 8), width=130, height=4)
headers_entry1.grid(column=1, row=2, sticky='w', padx=10, pady=5)
ttk.Label(tab1, text="params :").grid(column=0, row=3, sticky='w', padx=10, pady=5)
params_entry1 = tk.Text(tab1, font=('Arial', 8), width=130, height=4)
params_entry1.grid(column=1, row=3, sticky='w', padx=10, pady=5)

ttk.Label(tab1, text="cookies :").grid(column=0, row=4, sticky='w', padx=10, pady=5)
cookies_entry1 = tk.Text(tab1, font=('Arial', 8), width=130, height=4)
cookies_entry1.grid(column=1, row=4, sticky='w', padx=10, pady=5)


button1 = ttk.Button(tab1, text="  Get Keys  ", command=execute_script1)
button1.grid(column=1, row=5, pady=10)

ttk.Label(tab1, text="Download URL* :").grid(column=0, row=6, sticky='w', padx=10, pady=5)
download_url_entry1 = ttk.Entry(tab1, font=('Arial', 8), width=130)
download_url_entry1.grid(column=1, row=6, sticky='w', padx=10, pady=5)

ttk.Label(tab1, text="Video Name* :").grid(column=0, row=7, sticky='w', padx=10, pady=5)
video_name_entry1 = ttk.Entry(tab1, font=('Arial', 8), width=130)
video_name_entry1.grid(column=1, row=7, sticky='w', padx=10, pady=5)

ttk.Label(tab1, text="Save Location* :").grid(column=0, row=8, sticky='w', padx=10, pady=5)
save_direcion_entry1 = ttk.Entry(tab1, font=('Arial', 8), width=130)
save_direcion_entry1.grid(column=1, row=8, sticky='w', padx=10, pady=5)

download_button1 = ttk.Button(tab1, text="   Download   ", command=execute_download1)
download_button1.grid(column=1, row=9, pady=10)

# TAB 2
ttk.Label(tab2, text="PSSH* :").grid(column=0, row=0, sticky='w', padx=10, pady=5)
pssh_entry2 = ttk.Entry(tab2, font=('Arial', 8), width=130)
pssh_entry2.grid(column=1, row=0, sticky='w', padx=10, pady=5)

ttk.Label(tab2, text="License URL* :").grid(column=0, row=1, sticky='w', padx=10, pady=5)
url_entry2 = ttk.Entry(tab2, font=('Arial', 8), width=130)
url_entry2.grid(column=1, row=1, sticky='w', padx=10, pady=5)

ttk.Label(tab2, text="Headers :").grid(column=0, row=2, sticky='w', padx=10, pady=5)
headers_entry2 = tk.Text(tab2, font=('Arial', 8), width=130, height=4)
headers_entry2.grid(column=1, row=2, sticky='w', padx=10, pady=5)

button2 = ttk.Button(tab2, text="   Get Keys   ", command=execute_script2)
button2.grid(column=1, row=3, pady=10)

ttk.Label(tab2, text="Download URL* :").grid(column=0, row=4, sticky='w', padx=10, pady=5)
download_url_entry2 = ttk.Entry(tab2, font=('Arial', 8), width=130)
download_url_entry2.grid(column=1, row=4, sticky='w', padx=10, pady=5)

ttk.Label(tab2, text="Video Name* :").grid(column=0, row=5, sticky='w', padx=10, pady=5)
video_name_entry2 = ttk.Entry(tab2, font=('Arial', 8), width=130)
video_name_entry2.grid(column=1, row=5, sticky='w', padx=10, pady=5)

ttk.Label(tab2, text="Save Location* :").grid(column=0, row=6, sticky='w', padx=10, pady=5)
save_direcion_entry2 = ttk.Entry(tab2, font=('Arial', 8), width=130)
save_direcion_entry2.grid(column=1, row=6, sticky='w', padx=10, pady=5)

download_button2 = ttk.Button(tab2, text="   Download   ", command=execute_download2)
download_button2.grid(column=1, row=7, pady=10)

# TAB 3
ttk.Label(tab3, text="PSSH* :").grid(column=0, row=0, sticky='w', padx=10, pady=5)
pssh_entry3 = ttk.Entry(tab3, font=('Arial', 8), width=130)
pssh_entry3.grid(column=1, row=0, sticky='w', padx=10, pady=5)

ttk.Label(tab3, text="License URL* :").grid(column=0, row=1, sticky='w', padx=10, pady=5)
url_entry3 = ttk.Entry(tab3, font=('Arial', 8), width=130)
url_entry3.grid(column=1, row=1, sticky='w', padx=10, pady=5)

ttk.Label(tab3, text="Payload DATA* :").grid(column=0, row=2, sticky='w', padx=10, pady=5)

value1_entry3 = ttk.Entry(tab3, font=('Arial', 8))
value1_entry3.grid(column=0, row=3, sticky='w', padx=10, pady=5)

value1value_entry3 = tk.Text(tab3, font=('Arial', 8), height=1, width=130)
value1value_entry3.grid(column=1, row=3, sticky='w', padx=10, pady=5)

value2_entry3 = ttk.Entry(tab3, font=('Arial', 8))
value2_entry3.grid(column=0, row=4, sticky='w', padx=10, pady=5)

value2value_entry3 = tk.Text(tab3, font=('Arial', 8), height=1, width=130)
value2value_entry3.grid(column=1, row=4, sticky='w', padx=10, pady=5)

value3_entry3 = ttk.Entry(tab3, font=('Arial', 8))
value3_entry3.grid(column=0, row=5, sticky='w', padx=10, pady=5)

value3value_entry3 = tk.Text(tab3, font=('Arial', 8), height=1, width=130)
value3value_entry3.grid(column=1, row=5, sticky='w', padx=10, pady=5)

value4_entry3 = ttk.Entry(tab3, font=('Arial', 8))
value4_entry3.grid(column=0, row=6, sticky='w', padx=10, pady=5)

value4value_entry3 = tk.Text(tab3, font=('Arial', 8), height=1, width=130)
value4value_entry3.grid(column=1, row=6, sticky='w', padx=10, pady=5)

value5_entry3 = ttk.Entry(tab3, font=('Arial', 8))
value5_entry3.grid(column=0, row=7, sticky='w', padx=10, pady=5)
value5_entry3.insert(0, 'widevineChallenge')


value5value_entry3 = ttk.Entry(tab3, font=('Arial', 8), width=130)
value5value_entry3.grid(column=1, row=7, sticky='w', padx=10, pady=5)
value5value_entry3.insert(0, 'str(request, "utf-8")')
value5value_entry3.configure(state='readonly')

ttk.Label(tab3, text="Params :").grid(column=0, row=8, sticky='w', padx=10, pady=5)
params_entry3 = tk.Text(tab3, font=('Arial', 8), width=130, height=4)
params_entry3.grid(column=1, row=8, sticky='w', padx=10, pady=5)

ttk.Label(tab3, text="Headers :").grid(column=0, row=9, sticky='w', padx=10, pady=5)
headers_entry3 = tk.Text(tab3, font=('Arial', 8), width=130, height=4)
headers_entry3.grid(column=1, row=9, sticky='w', padx=10, pady=5)

ttk.Label(tab3, text="Cookies :").grid(column=0, row=10, sticky='w', padx=10, pady=5)
cookies_entry3 = tk.Text(tab3, font=('Arial', 8), width=130, height=4)
cookies_entry3.grid(column=1, row=10, sticky='w', padx=10, pady=5)


button3 = ttk.Button(tab3, text="   Get Keys   ", command=execute_script3)
button3.grid(column=1, row=11, pady=10)

ttk.Label(tab3, text="Download URL* :").grid(column=0, row=12, sticky='w', padx=10, pady=5)
download_url_entry3 = ttk.Entry(tab3, font=('Arial', 8), width=130)
download_url_entry3.grid(column=1, row=12, sticky='w', padx=10, pady=5)

ttk.Label(tab3, text="Video Name* :").grid(column=0, row=13, sticky='w', padx=10, pady=5)
video_name_entry3 = ttk.Entry(tab3, font=('Arial', 8), width=130)
video_name_entry3.grid(column=1, row=13, sticky='w', padx=10, pady=5)

ttk.Label(tab3, text="Save Location* :").grid(column=0, row=14, sticky='w', padx=10, pady=5)
save_direcion_entry3 = ttk.Entry(tab3, font=('Arial', 8), width=130)
save_direcion_entry3.grid(column=1, row=14, sticky='w', padx=10, pady=5)

download_button3 = ttk.Button(tab3, text="   Download   ", command=execute_download3)
download_button3.grid(column=1, row=15, pady=10)

# TAB 4
ttk.Label(tab4, text="PSSH* :").grid(column=0, row=0, sticky='w', padx=10, pady=5)
pssh_entry4 = ttk.Entry(tab4, font=('Arial', 8), width=130)
pssh_entry4.grid(column=1, row=0, sticky='w', padx=10, pady=5)

ttk.Label(tab4, text="License URL* :").grid(column=0, row=1, sticky='w', padx=10, pady=5)
url_entry4 = ttk.Entry(tab4, font=('Arial', 8), width=130)
url_entry4.grid(column=1, row=1, sticky='w', padx=10, pady=5)

ttk.Label(tab4, text="Request Payload* :").grid(column=0, row=2, sticky='w', padx=10, pady=5)
payload_entry4 = tk.Text(tab4, font=('Arial', 8), width=130, height=3)
payload_entry4.grid(column=1, row=2, sticky='w', padx=10, pady=5)

data_info_entry4 = ttk.Entry(tab4, font=('Arial', 8), width=130)
data_info_entry4.grid(column=1, row=3, sticky='w', padx=10, pady=5)

ttk.Label(tab4, text="Headers :").grid(column=0, row=4, sticky='w', padx=10, pady=5)
headers_entry4 = tk.Text(tab4, font=('Arial', 8), width=130, height=4)
headers_entry4.grid(column=1, row=4, sticky='w', padx=10, pady=5)

ttk.Label(tab4, text="Params :").grid(column=0, row=5, sticky='w', padx=10, pady=5)
params_entry4 = tk.Text(tab4, font=('Arial', 8), width=130, height=4)
params_entry4.grid(column=1, row=5, sticky='w', padx=10, pady=5)

ttk.Label(tab4, text="Cookies :").grid(column=0, row=6, sticky='w', padx=10, pady=5)
cookies_entry4 = tk.Text(tab4, font=('Arial', 8), width=130, height=4)
cookies_entry4.grid(column=1, row=6, sticky='w', padx=10, pady=5)


button4 = ttk.Button(tab4, text="   Get Keys   ", command=execute_script4)
button4.grid(column=1, row=7, pady=10)

ttk.Label(tab4, text="Download URL* :").grid(column=0, row=8, sticky='w', padx=10, pady=5)
download_url_entry4 = ttk.Entry(tab4, font=('Arial', 10), width=111)
download_url_entry4.grid(column=1, row=8, sticky='w', padx=10, pady=5)

ttk.Label(tab4, text="Video Name* :").grid(column=0, row=9, sticky='w', padx=10, pady=5)
video_name_entry4 = ttk.Entry(tab4, font=('Arial', 10), width=111)
video_name_entry4.grid(column=1, row=9, sticky='w', padx=10, pady=5)

ttk.Label(tab4, text="Save Location* :").grid(column=0, row=10, sticky='w', padx=10, pady=5)
save_direcion_entry4 = ttk.Entry(tab4, font=('Arial', 10), width=111)
save_direcion_entry4.grid(column=1, row=10, sticky='w', padx=10, pady=5)

download_button4 = ttk.Button(tab4, text="   Download   ", command=execute_download4)
download_button4.grid(column=1, row=11, pady=10)

#TAB 5
ttk.Label(tab5, text="Episode URL* :").grid(column=0, row=0, sticky='w', padx=10, pady=5)
url_entry5 = ttk.Entry(tab5, font=('Arial', 8), width=130)
url_entry5.grid(column=1, row=0, sticky='w', padx=10, pady=5)

button5 = ttk.Button(tab5, text="   Get Keys   ", command=execute_script5)
button5.grid(column=1, row=2, pady=10)

ttk.Label(tab5, text="Download URL* :").grid(column=0, row=3, sticky='w', padx=10, pady=5)
download_url_entry5 = ttk.Entry(tab5, font=('Arial', 10), width=111)
download_url_entry5.grid(column=1, row=3, sticky='w', padx=10, pady=5)

ttk.Label(tab5, text="Video Name* :").grid(column=0, row=4, sticky='w', padx=10, pady=5)
video_name_entry5 = ttk.Entry(tab5, font=('Arial', 10), width=111)
video_name_entry5.grid(column=1, row=4, sticky='w', padx=10, pady=5)

ttk.Label(tab5, text="Save Location* :").grid(column=0, row=5, sticky='w', padx=10, pady=5)
save_direcion_entry5 = ttk.Entry(tab5, font=('Arial', 10), width=111)
save_direcion_entry5.grid(column=1, row=5, sticky='w', padx=10, pady=5)

download_button5 = ttk.Button(tab5, text="   Download   ", command=execute_download5)
download_button5.grid(column=1, row=6, pady=10)


# Result box
result_box = scrolledtext.ScrolledText(window)
result_box.pack(pady=10, expand=True, fill='both')

window.after(2000, update_data_name)  
window.mainloop()
