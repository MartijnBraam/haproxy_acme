import os
import argparse
import configparser
from haproxy_acme.acme import acme_register
from haproxy_acme.private import make_private_key_rsa
from haproxy_acme.writer import write_pem


def run_config(config):
    account_key = os.path.join(config.get('general', 'data-dir'), 'account.key')
    if not os.path.isfile(account_key):
        key = make_private_key_rsa()
        write_pem(account_key, key)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="HAProxy ACME client")
    parser.add_argument('configfile', help='Path to the config file')
    args = parser.parse_args()

    config = configparser.ConfigParser()
    config.read(args.configfile)

    run_config(config)
