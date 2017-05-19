import os
import re


def process_http01_challenge(challenge, thumbprint, directory):
    token = re.sub(r"[^A-Za-z0-9_\-]", "_", challenge['token'])
    keyauthorization = "{}.{}".format(token, thumbprint)

    with open(os.path.join(directory, token), 'w') as handle:
        handle.write(keyauthorization)

    return keyauthorization
