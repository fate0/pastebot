# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import click
import pastebot

click.disable_unicode_literals_warning = True
CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(pastebot.__version__)
@click.option("--token", help="微博 access token")
def main(token):
    pass


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option("--key", help="微博 App Key")
@click.option("--secret", help="微博 App Secret")
@click.option("--domain", help="微博安全域名")
def weibo(key, secret, domain):
    """生成 weibo access token"""
    wb = pastebot.WeiBo()
    wb.app_key = key
    wb.app_secret = secret
    wb.secure_domain = domain

    result = wb.exchange_access_token()

    click.echo(result)
    click.echo('返回 access_token: {}'.format(result['access_token']))
    click.echo('过期时间: {}h'.format(int(result['expires_in']) / (60 * 60)))
    click.echo('用户 uid: {}'.format(result['uid']))
