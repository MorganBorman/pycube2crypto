"""A python native implementation of the public key crypto in Cube 2
Based on the Sauerbraten Sources and https://github.com/mgaare/cube2-crypto

The tiger implementation (tiger.py and sboxes.py) is from https://github.com/browning/tiger-hash-python
See the license and copyright included in those files.
"""

from gfield import GField
from jacobian import Jacobian
import ecc_params
import tiger
from get_random_number import get_random_number

def hash_string(string):
    h = tiger.hash(string)
    a, b, c = map(list, (h[0:16], h[16:32], h[32:48]))
    map(lambda s: s.reverse(), (a, b, c))
    return (''.join(a+b+c)).lower()

def parse_private_key(private_key_str, ecc_params=ecc_params):
    private_key = int(private_key_str, 16)
    return GField(private_key, ecc_params)
    
def parse_public_key(public_key_str, ecc_params=ecc_params):
    return Jacobian.parse(public_key_str, ecc_params)

def get_public_key(private_key, ecc_params=ecc_params):
    if isinstance(private_key, str):
        private_key = parse_private_key(private_key, ecc_params)

    assert isinstance(private_key, GField)
    
    return Jacobian.base(ecc_params).mul(private_key).normalize()
    
def generate_key_pair(ecc_params=ecc_params):
    private_key = GField(get_random_number(24), ecc_params)
    public_key = get_public_key(private_key)
    return (private_key, public_key)

def answer_challenge(private_key, challenge, ecc_params=ecc_params):
    if isinstance(private_key, str):
        private_key = parse_private_key(private_key, ecc_params)
        
    if isinstance(challenge, str):
        challenge = Jacobian.parse(challenge, ecc_params)

    assert isinstance(private_key, GField)
    assert isinstance(challenge, Jacobian)
    
    return challenge.mul(private_key).normalize().x

def generate_challenge(public_key, ecc_params=ecc_params):
    if isinstance(public_key, str):
        public_key = parse_public_key(public_key, ecc_params)
    
    assert isinstance(public_key, Jacobian)
    
    secret = GField(get_random_number(24), ecc_params)
    challenge = Jacobian.base(ecc_params).mul(secret).normalize()
    answer = public_key.mul(secret).normalize().x
    return (challenge, answer)

if __name__ == '__main__':
    stringhashes = [
        {'string': '', 'hash': '2339ca36c0310f42f529bb1b67e66161a7e48594d2ed373f'},
        {'string': 'a', 'hash': '77ebbffee2e78fbae28c9fb35f787acf16e342f7f5428790'},
        {'string': 'abc', 'hash': 'a2ba41488e1c852ffb8b5cff145ba725159231c159b7f539'},
        {'string': 'message digest', 'hash': '9d188fbc8702a159d0fc038457e144c115f7aca15aa5926f'},
        {'string': 'abcdefghijklmnopqrstuvwxyz', 'hash': '71414a27ee5ed703404021fbcc5530a2b01106f23fb7ee9e'},
        {'string': 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq', 'hash': 'f0b79f1ab9c9852f7b16d07f8ef4a03c7ac136e1b7357fe8'},
    ]

    authkeys = [
        {'private': 'f373de2d49584e7a16166e76b1bb925f24f0130c63ac9332', 'public': '+2c1fb1dd4f2a7b9d81320497c64983e92cda412ed50f33aa'},
        {'private': '0978245f7f243e61fca787f53bf9c82eabf87e2eeffbbe77', 'public': '-afe5929327bd76371626cce7585006067603daf76f09c27e'},
        {'private': '935f7b951c132951527ab541ffc5b8bff258c1e88414ab2a', 'public': '-d954ee56eddf2b71e206e67d48aaf4afe1cc70f8ca9d1058'},
        {'private': 'f6295aa51aca7f511c441e754830cf0d951a2078cbf881d9', 'public': '-454c98466c45fce242724e6e989bdd9f841304a1fcba4787'},
        {'private': 'e9ee7bf32f60110b2a0355ccbf120404307de5ee72a41417', 'public': '+15fda493cb1095ca40f652b0d208769bd42b9e234e48d1a8'},
        {'private': '8ef7537b1e631ca7c30a4fe8f70d61b7f2589c9ba1f97b0f', 'public': '+643d99cb21178557f4e965eb6dc1ec1e4f57b3b05375fafb'},
    ]
    
    import unittest
    import cube2crypto
    from Crypto import Random

    class TestCube2Crypto(unittest.TestCase):

        def test_hash_strings(self):
            for stringhash in stringhashes:
                self.assertEqual(stringhash['hash'], hash_string(stringhash['string']))
                
        def test_public_key_recovery(self):
            for authkey in authkeys:
                self.assertEqual(authkey['public'], str(get_public_key(authkey['private'])))
                
        def test_challenges_native_to_py(self):
            for authkey in authkeys:
                generated_challenge = cube2crypto.genchallenge(authkey['public'], repr(Random.get_random_bytes(24)))
                answer = answer_challenge(authkey['private'], generated_challenge[0])
                
                self.assertEqual(generated_challenge[1], str(answer))

        def test_challenges_py_to_native(self):
            for authkey in authkeys:
                generated_challenge = generate_challenge(authkey['public'])
                answer = cube2crypto.answerchallenge(authkey['private'], str(generated_challenge[0]))
                
                self.assertEqual(str(generated_challenge[1]), answer)

    suite = unittest.TestLoader().loadTestsFromTestCase(TestCube2Crypto)
    unittest.TextTestRunner(verbosity=2).run(suite)
    
