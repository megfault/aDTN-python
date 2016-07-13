from pathlib import Path
from nacl.secret import SecretBox
from nacl.utils import random
from nacl.hash import sha256
from nacl.encoding import HexEncoder
from argparse import ArgumentParser

from pyadtn.utils import b2s, s2b
from pyadtn.settings import DEFAULT_DIR, KEYS_DIR

from logging import basicConfig, debug, DEBUG
basicConfig(filename='key_manager.log', level=DEBUG,
            format='[%(relativeCreated)8d] %(message)s', )


class KeyManager():
    def __init__(self):
        self.keys = dict()
        self.load_keys()

    def create_key(self, key_id=None):
        key = random(SecretBox.KEY_SIZE)
        if not key_id:
            h = sha256(key, HexEncoder)
            key_id = h.decode('utf-8')[:16]
        self.keys[key_id] = key
        debug("Key {} was created.".format(key_id))
        self.save_key(key_id)
        return key_id

    def get_fake_key(self):
        return random(SecretBox.KEY_SIZE)

    def save_key(self, key_id, directory=DEFAULT_DIR):
        path = Path(directory + KEYS_DIR)
        file_path = path.joinpath(key_id + ".key")
        if not file_path.exists():
            key = self.keys[key_id]
            s = b2s(key)
            with file_path.open('w', encoding='utf-8') as f:
                f.write(s)
            debug("Key {} was written to disk".format(key_id))

    def save_all_keys(self):
        for key_id in self.keys:
            self.save_key(key_id)

    def load_keys(self, directory=DEFAULT_DIR):
        path = Path(directory + KEYS_DIR)
        for file_path in path.iterdir():
            if file_path.suffix == ".key":
                with file_path.open('r', encoding='utf-8') as f:
                    s = f.readline()
                key = s2b(s)
                self.keys[file_path.stem] = key


def parse_args():
    parser = ArgumentParser(description='Manage aDTN keys')
    parser.add_argument('-c', metavar="filename", type=str, dest="key_name", default=None, help='create a key and store it in <filename>.key in the keys directory')
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_args()
    if args.key_name is not None:
        km = KeyManager()
        km.create_key(args.key_name)
