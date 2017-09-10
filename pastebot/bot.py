# -*- coding: utf-8 -*-

from __future__ import unicode_literals, division

import os
import sys
import time
import yara
import raven
import queue
import signal
import logging
import requests
import threading
from .weibo import WeiBo


logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.ERROR)


_signames = dict((getattr(signal, signame), signame)
                 for signame in dir(signal)
                 if signame.startswith('SIG') and '_' not in signame)


def signal_name(signum):
    try:
        if sys.version_info[:2] >= (3, 5):
            return signal.Signals(signum).name
        else:
            return _signames[signum]

    except KeyError:
        return 'SIG_UNKNOWN'
    except ValueError:
        return 'SIG_UNKNOWN'


class PasteBot(object):
    def __init__(self):
        self.rules = yara.compile('./rules/index.yar')
        self.paste_queue = queue.Queue()
        self.last_query_result = []
        self.last_query_time = 0
        self.last_query_lock = threading.Lock()
        self.sentry_api = None
        self.pastebin_api = "https://pastebin.com/api_scraping.php"
        self.pastebin_post_api = 'https://pastebin.com/api/api_post.php'
        self.stopped = False
        self.request_timeout = 5
        self.thread_pool = []
        self.thread_pool_size = 10
        self.sentry_client = None
        self.qps = 1

    def _install_signal_handlers(self):
        signal.signal(signal.SIGINT, self.request_stop)
        signal.signal(signal.SIGTERM, self.request_stop)

    def request_stop(self, signum, _):
        logger.info('Got signal {0}'.format(signal_name(signum)))
        logger.info('Warm shut down requested')

        signal.signal(signal.SIGINT, self.request_force_stop)
        signal.signal(signal.SIGTERM, self.request_force_stop)

        self.stopped = True
        logger.info('Press Ctrl+C again for a cold shutdown.')

    def request_force_stop(self, signum, _):
        raise SystemExit

    def new_weibo_post(self, paste_info, result):
        print(paste_info, result)

    def fetch_and_parse(self):
        while not self.stopped:
            try:
                paste_info = self.paste_queue.get(timeout=1)
            except queue.Empty:
                continue
            except Exception:
                logger.error("Unknown exception", exc_info=True)
                self.sentry_client.captureException()
                continue

            logger.debug("get task %s" % paste_info)

            # qps 设置
            with self.last_query_lock:
                cur_time = time.time()
                delay_time = 1 / self.qps
                if cur_time - self.last_query_time < delay_time:
                    time.sleep(delay_time - (cur_time - self.last_query_time))

                self.last_query_time = time.time()
                print(time.time())

            try:
                rp = requests.get(paste_info['scrape_url'], timeout=5)
            except requests.Timeout:
                continue
            except Exception:
                logger.error("Unknown exception", exc_info=True)
                continue

            result = self.rules.match(data=rp.content)
            if not result:
                continue

            self.new_weibo_post(paste_info, result)

    def start(self):
        self._install_signal_handlers()
        self.sentry_client = raven.Client(self.sentry_api)

        for i in range(self.thread_pool_size):
            t = threading.Thread(target=self.fetch_and_parse)
            t.start()

            self.thread_pool.append(t)

        while not self.stopped:
            time.sleep(3)

            try:
                rp = requests.get(self.pastebin_api, timeout=self.request_timeout)
            except requests.Timeout:
                continue
            except Exception:
                logger.error("Unknown exception", exc_info=True)
                continue

            try:
                pastes_info = rp.json()
            except Exception:
                logger.error("Unknown exception", exc_info=True)
                print(rp.text)
                continue

            for each_paste_info in pastes_info:
                if each_paste_info not in self.last_query_result:
                    self.paste_queue.put(each_paste_info)
                    logger.debug("push task")

            self.last_query_result = pastes_info

        for t in self.thread_pool:
            t.join()


if __name__ == '__main__':
    pb = PasteBot()
    pb.start()
