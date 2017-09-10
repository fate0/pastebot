# pastebot

[pastebot](http://weibo.com/pastebot) 是一个监控 pastebin 的敏感内容，并发微博的 bot

### 安装

使用 pip 安装:
```
$ pip install -U pastebot
```

或使用 GitHub 安装
```
$ pip install -U git+https://github.com/fate0/pastebot.git
```

或使用源码安装:

```
$ python setup.py install
```

### 使用

基本命令:

```
$ pastebot
Usage: pastebot [OPTIONS] COMMAND [ARGS]...

Options:
  --version   Show the version and exit.
  -h, --help  Show this message and exit.

Commands:
  serve  开始运行 pastebot
  weibo  生成 weibo access token
```

生成 weibo access token

```
$ pastebot weibo -h
Usage: pastebot weibo [OPTIONS]

  生成 weibo access token

Options:
  --key TEXT     微博 App Key  [required]
  --secret TEXT  微博 App Secret  [required]
  --domain TEXT  微博安全域名  [required]
  -h, --help     Show this message and exit.
  
$ pastebot weibo --key 1234 --secret 123123123123 --domain yourodmain.com
input auth_code: asdfsdfsdf

返回 access_token: you_access_token
过期时间: 37.329166666666666h
用户 uid: 111111

```

使用 `pastebot serve` 运行监控

```
$ pastebot serve -h
Usage: pastebot serve [OPTIONS]

  开始运行 pastebot

Options:
  --token TEXT     微博 access token  [required]
  --dsn TEXT       sentry dsn
  --pool INTEGER   线程池大小
  --qps FLOAT      qps
  --timeout FLOAT  请求 timeout
  -h, --help       Show this message and exit.

$ pastebot serve --token you_access_token
```

### 参考

* [PasteHunter](https://github.com/kevthehermit/PasteHunter)
* [dumpmon](https://github.com/jordan-wright/dumpmon)

