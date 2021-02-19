# py-r10k-webhook
ultra lightweight and flexible webhook for Puppet code deployment with r10k 

<!-- vscode-markdown-toc -->
* 1. [Motivation](#Motivation)
* 2. [Dependencies](#Dependencies)
* 3. [Params](#Params)
* 4. [Example config.ini](#Exampleconfig.ini)
* 5. [Installation](#Installation)
* 6. [Testing](#Testing)
* 7. [Limitations](#Limitations)

<!-- vscode-markdown-toc-config
	numbering=true
	autoSave=true
	/vscode-markdown-toc-config -->
<!-- /vscode-markdown-toc -->

##  1. <a name='Motivation'></a>Motivation
There are several other r10k webhooks out there. But I could not find any hook, that is easy to debug, supports ipv6, supports SSL, has minimal dependencies *and* logs the output of r10k. So here comes the simple and lightweight py-r10k-webhook.

##  2. <a name='Dependencies'></a>Dependencies
The webhook requires python3 and the following modules. Most of them should be part of your distro's python3 base package:
* `os, sys, syslog, socket, ssl, base64, threading`
* `json`
* `configparser`
* `http.server`

##  3. <a name='Params'></a>Params
* `[main]`
  * `listen_addr` mandatory. Supports ipv4 and ipv6
  * `listen_port` mandatory. Specify port to listen on

* `[r10k]`
  * `r10k_environment_command` optional. Defaults to `r10k deploy environment "$R10KENV" -pv`, $R10KENV is the environment from payload
  * `r10k_module_command` optional. Defaults to `r10k deploy module "$R10KMODULE" -v`, $R10KMODULE is the modulename.  
  Note: If the name in payload is 'puppetlabs-apt', the $R10KMODULE is then 'apt'.  
  Note: This setting may be useful for those who want to execute a r10k postrun. Currently r10k does no postrun after module deployment, see also [this issue](https://github.com/puppetlabs/r10k/issues/982).

* `[ssl]`
  * `ssl_key` optional. Has to come with 'ssl_cert'. Hook is using HTTP, if the ssl section is absent.
  * `ssl_cert` optional. Has to come with 'ssl_key'. Hook is using HTTP, if the ssl section is absent.
  * `ssl_ca` optional, SSL socket is beeing used without ca, if left out

* `[auth]`
  * `user` optional. Has to come with 'pass'. Basic auth is not beeing used, if section auth is absent.
  * `pass` optional. Has to come with 'user'. Basic auth is not beeing used, if section auth is absent.


##  4. <a name='Exampleconfig.ini'></a>Example config.ini
```
[main]
listen_addr = ::   
listen_port = 8443

[r10k]
r10k_module_command = r10k deploy module "$R10KMODULE" -v; /my/post/hook/script "$R10KMODULE"
r10k_environment_command = r10k deploy environment "$R10KENV" -pv; /my/fancy/slack/plugin "$R10KENV"

[ssl]
ssl_cert = /etc/ssl/hook.pem
ssl_key = /etc/ssl/private/hook.pem
ssl_ca = /etc/ssl/ca.pem

[auth]
user = iamgood
pass = letmein
```

##  5. <a name='Installation'></a>Installation
You just need the file `py-r10k-webhook`, your config.ini file (see below) and a systemd service file:

```ini
[Unit]
Description=py-r10k-webhook
Conflicts=shutdown.target
After=network.target network-online.target
Wants=network-online.target
StartLimitInterval=25
StartLimitBurst=3

[Service]
Type=simple
ExecStart=/path/to/py-r10k-webhook /path/to/py-r10k-webhook.conf
KillMode=process
Restart=on-failure
RestartSec=5

[Install]
WantedBy=graphical.target
```
Note: This is an just-working exmaple unit file. For securing the service please refer to [systemd-analyze security](https://www.freedesktop.org/software/systemd/man/systemd-analyze.html#systemd-analyze%20security%20%5BUNIT...%5D)

One could configure all parts using puppet. For that you'll need the modules [vcsrepo](https://forge.puppet.com/puppetlabs/vcsrepo), [inifile](https://forge.puppet.com/modules/puppetlabs/inifile) and [systemd](https://forge.puppet.com/modules/camptocamp/systemd).

##  6. <a name='Testing'></a>Testing

Test your configs by following the logs:
```
journalctl -fu py-r10k-webhook.service &
```

… and trigger environment deployment, e.g. production:
```
curl -X POST -H "Content-Type: application/json" -H "X-Gitlab-Event: Push Hook" -d '{ "ref": "production" }' https://user:pass@host:port/api/v1/r10k/environment/
```

… and trigger module deployment, e.g. my-puppetmodule:
```
curl -X POST -H "Content-Type: application/json" -H "X-Gitlab-Event: Push Hook" -d '{ "project": { "name": "my-puppetmodule" }}' https://user:pass@host:port/api/v1/r10k/module/
```

##  7. <a name='Limitations'></a>Limitations
* Currently, there's only gitlab supported. More information about gitlab hooks can be found [here](https://docs.gitlab.com/ee/user/project/integrations/webhooks.html#webhook-endpoint-tips) and [here](https://docs.gitlab.com/ee/user/project/integrations/webhooks.html#push-events)
* Logging facilitiy is currently hard-coded local0. One may implement more complex logging libraries for higher requirements.
* One could improve thread handling as there's currently no errorhandling on started threads.
* There are no automated Code Tests, but the hook is working stable on Ubuntu focal (20.04) and Python 3.8.5 :smile:
