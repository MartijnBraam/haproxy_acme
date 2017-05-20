# Haproxy ACME client

This a client that manages ACME (Lets Encrypt) certificates for HAProxy with both ECDSA and RSA certificates.

## Installation

From pypi:

```bash
$ apt install python3-requests
$ pip install cryptography
```

Starting from Debian 9 the requirements are in the repositories

```bash
$ apt install python3-cryptograpy python3-requests
```

Finishing the installation:

```bash
$ mkdir /etc/acme
$ cp config.ini.example /etc/acme/config.ini
$ edit /etc/acme/config.ini
```

## Running

```bash
$ python3 -m haproxy_acme /etc/acme/config.ini
```

This will request/update certificates if necessary, you can run this command with cron daily