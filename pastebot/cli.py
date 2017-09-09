# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import click
import pastebot

click.disable_unicode_literals_warning = True
CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(pastebot.__version__)
@click.option("pb-key", help="pastebin api key")
@click.option("wb-key", help="weibo api key")
def main():
    pass