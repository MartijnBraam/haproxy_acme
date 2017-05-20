import os
import argparse
import configparser
from datetime import datetime

import haproxy_acme.acme as acme
from haproxy_acme.private import make_private_key_rsa
from haproxy_acme.writer import write_pem, read_pem


def _ensure_dir(config, name):
    full = os.path.join(config.get('general', 'data-dir'), name)
    if not os.path.isdir(full):
        os.makedirs(full)


def get_cert_age(config, section):
    cert = config.get(section, 'domains').split(',')[0]
    key_dir = config.get('general', 'data-dir')
    crt = os.path.join(key_dir, 'live', '{}.crt.rsa'.format(cert))
    certificate = read_pem(crt)
    validity = certificate.not_valid_after
    today = datetime.now()
    diff = validity - today
    return diff.days


def process_domain(config, section):
    min_age = int(config.get('general', 'renewal-age', fallback="20"))
    age = get_cert_age(config, section)
    if age > min_age:
        return

    dsn = {
        'country': config.get(section, 'country'),
        'state': config.get(section, 'state'),
        'locality': config.get(section, 'locality'),
        'organisation': config.get(section, 'organisation'),
    }
    domains = config.get(section, 'domains').split(',')
    verfiy_dir = config.get('general', 'verify-dir')
    acme.verify_domain(domains, verfiy_dir, config.get('general', 'data-dir'), dsn)


def run_config(config):
    account_key = os.path.join(config.get('general', 'data-dir'), 'account.key')

    _ensure_dir(config, 'csr')
    _ensure_dir(config, 'private')
    _ensure_dir(config, 'live')

    acme.server = config.get('general', 'server')

    if os.path.isfile(account_key):
        key = read_pem(account_key)
    else:
        key = make_private_key_rsa()
        write_pem(account_key, key)
    acme.key = key
    acme.register(config.get('general', 'email'), config.get('general', 'agreement'))

    for section in config.sections():
        if section not in ["general"]:
            process_domain(config, section)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="HAProxy ACME client")
    parser.add_argument('configfile', help='Path to the config file')
    args = parser.parse_args()

    config = configparser.ConfigParser()
    config.read(args.configfile)

    run_config(config)
