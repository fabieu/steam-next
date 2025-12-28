import re
from getpass import getpass

import steam.webauth as wa

user_input = input
username = user_input("Username: ")
password = getpass("Password: ")

webclient = wa.WebAuth(username, password)

try:
    webclient.login()
except wa.EmailCodeRequired:
    webclient.login(code=user_input("Email code: "))
except wa.TwoFactorCodeRequired:
    webclient.login(code=user_input("2FA code: "))

if webclient.logged_on:
    resp = webclient.session.get('https://store.steampowered.com/account/store_transactions/')
    resp.raise_for_status()
    balance = re.search(r'store_transactions/">(?P<balance>.*?)</a>', resp.text).group('balance')
    print("Current balance: %s" % balance)
