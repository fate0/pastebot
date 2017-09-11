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
        rule_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'rules/index.yar')
        self._rules = yara.compile(rule_path)
        self._paste_queue = queue.Queue()
        self._last_query_result = []
        self._last_query_time = 0
        self._last_query_lock = threading.Lock()

        self._pastebin_api = "https://pastebin.com/api_scraping.php"
        self._stopped = False

        self._thread_pool = []
        self._sentry_client = None
        self._weibo_client = None

        # 用户可设置属性
        self.qps = 1
        self.sentry_dsn = None
        self.request_timeout = 5
        self.thread_pool_size = 10
        self.weibo_access_token = None

    @property
    def weibo_client(self):
        if not self._weibo_client:
            self._weibo_client = WeiBo()
            self._weibo_client.access_token = self.weibo_access_token

        return self._weibo_client

    @property
    def sentry_client(self):
        if not self._sentry_client:
            self._sentry_client = raven.Client(self.sentry_dsn)

        return self._sentry_client

    def _install_signal_handlers(self):
        signal.signal(signal.SIGINT, self.request_stop)
        signal.signal(signal.SIGTERM, self.request_stop)

    def request_stop(self, signum, _):
        logger.info('Got signal {0}'.format(signal_name(signum)))
        logger.info('Warm shut down requested')

        signal.signal(signal.SIGINT, self.request_force_stop)
        signal.signal(signal.SIGTERM, self.request_force_stop)

        self._stopped = True
        logger.info('Press Ctrl+C again for a cold shutdown.')

    def request_force_stop(self, signum, _):
        raise SystemExit

    def new_weibo_post(self, paste_info, results):
        result_types = []
        result_num = 1
        for each_result in results:
            result_type = each_result.meta.get('type')
            if result_type:
                result_types.append(result_type)

            if len(each_result.strings) > result_num:
                result_num = len(each_result.strings)

        post_msg = "{}\n类型: {}".format(paste_info['full_url'], ",".join(result_types))
        if result_num > 1:
            post_msg += "\n数量: {}".format(result_num)
        if paste_info['title']:
            post_msg += "\n标题: {}".format(paste_info['title'])
        if paste_info['user']:
            post_msg += "\n作者: {}".format(paste_info['user'])

        try:
            print(post_msg)
            self.weibo_client.new_post(post_msg)
        except requests.Timeout:
            pass
        except Exception:
            logger.error("Unknown exception", exc_info=True)
            self.sentry_client.captureException()

    def fetch_and_parse(self):
        while not self._stopped:
            try:
                paste_info = self._paste_queue.get(timeout=1)
            except queue.Empty:
                continue
            except Exception:
                logger.error("Unknown exception", exc_info=True)
                self.sentry_client.captureException()
                continue

            logger.debug("get task %s" % paste_info)

            # qps 设置
            with self._last_query_lock:
                cur_time = time.time()
                delay_time = 1 / self.qps
                if cur_time - self._last_query_time < delay_time:
                    time.sleep(delay_time - (cur_time - self._last_query_time))

                self._last_query_time = time.time()

            try:
                rp = requests.get(paste_info['scrape_url'], timeout=5)
            except requests.Timeout:
                continue
            except Exception:
                logger.error("Unknown exception", exc_info=True)
                continue

            result = self._rules.match(data=rp.content)
            if not result:
                continue

            self.new_weibo_post(paste_info, result)

    def start(self):
        self._install_signal_handlers()

        for i in range(self.thread_pool_size):
            t = threading.Thread(target=self.fetch_and_parse)
            t.start()

            self._thread_pool.append(t)

        while not self._stopped:
            time.sleep(3)

            try:
                rp = requests.get(self._pastebin_api, timeout=self.request_timeout)
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
                if each_paste_info not in self._last_query_result:
                    self._paste_queue.put(each_paste_info)
                    logger.debug("push task")

            self._last_query_result = pastes_info

        for t in self._thread_pool:
            t.join()
