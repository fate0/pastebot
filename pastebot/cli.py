# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import click
import pastebot

click.disable_unicode_literals_warning = True
CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(pastebot.__version__)
def main():
    pass


@main.command(context_settings=CONTEXT_SETTINGS)
@click.option("--token", required=True, help="微博 access token")
@click.option("--dsn", default=None, help="sentry dsn")
@click.option("--pool", type=click.INT, default=10, help="线程池大小")
@click.option("--qps", type=click.FLOAT, default=1, help="qps")
@click.option("--timeout", type=click.FLOAT, default=5, help="请求 timeout")
def serve(token, dsn, pool, qps, timeout):
    """开始运行 pastebot"""
    pb = pastebot.PasteBot()
    pb.weibo_access_token = token
    pb.sentry_dsn = dsn

    if pool <= 0:
        raise click.BadParameter("线程池大小必须大于 0")
    pb.thread_pool_size = pool

    if qps <= 0:
        raise click.BadParameter("qps 必须大于 0")
    pb.qps = qps

    if timeout <= 0:
        raise click.BadParameter("timeout 必须大于 0")
    pb.request_timeout = timeout

    pb.start()


@main.command(context_settings=CONTEXT_SETTINGS)
@click.option("--key", required=True, help="微博 App Key")
@click.option("--secret", required=True, help="微博 App Secret")
@click.option("--domain", required=True, help="微博安全域名")
def weibo(key, secret, domain):
    """生成 weibo access token"""
    wb = pastebot.WeiBo()
    wb.app_key = key
    wb.app_secret = secret
    wb.secure_domain = domain

    result = wb.exchange_access_token()

    click.echo('返回 access_token: {}'.format(result['access_token']))
    click.echo('过期时间: {}h'.format(int(result['expires_in']) / (60 * 60)))
    click.echo('用户 uid: {}'.format(result['uid']))
