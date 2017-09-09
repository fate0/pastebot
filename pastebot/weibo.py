# -*- coding: utf-8 -*-

from __future__ import unicode_literals, division

import requests
import webbrowser


class WeiBo(object):
    def __init__(self):
        self.app_key = None
        self.app_secret = None
        self.secure_domain = None
        self.auth_code = None
        self.access_token = None
        self.sina_oauth2_authorize_url = 'https://api.weibo.com/oauth2/authorize?client_id={}&redirect_uri=http://{}'
        self.sina_oauth2_access_token_url = 'https://api.weibo.com/oauth2/access_token'
        self.sina_new_post_url = 'https://api.weibo.com/2/statuses/share.json'

    def exchange_auth_code(self):
        url = self.sina_oauth2_authorize_url.format(self.app_key, self.secure_domain)
        webbrowser.open(url)
        self.auth_code = input("input auth_code: ").strip()

    def exchange_access_token(self):
        if not self.auth_code:
            self.exchange_auth_code()

        data = {
            'client_id': self.app_key,
            'client_secret': self.app_secret,
            'grant_type': 'authorization_code',
            'code': self.auth_code,
            'redirect_uri': 'http://{}'.format(self.secure_domain)
        }

        rp = requests.post(self.sina_oauth2_access_token_url, data=data)
        result = rp.json()
        self.access_token = result['access_token']
        print(result)
        print('返回 access_token: {}'.format(result['access_token']))
        print('过期时间: {}h'.format(int(result['expires_in'])/(60*60)))
        print('用户 uid: {}'.format(result['uid']))

    def new_post(self, post):
        if not self.access_token:
            self.exchange_access_token()

        data = {
            'access_token': self.access_token,
            "status": post
        }
        rp = requests.post(self.sina_new_post_url, data=data)
        print(rp.text)


if __name__ == '__main__':
    wb = WeiBo()
    wb.secure_domain = 'your domain'
    wb.app_key = 'your key'
    wb.app_secret = 'your secret'
    wb.new_post('http://{} 你好啊'.format(wb.secure_domain))
