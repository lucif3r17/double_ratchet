import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES

def b64(msg):
    """ Base64 encoding helper """
    return base64.encodebytes(msg).decode('utf-8').strip()

def hkdf(inp, length):
    """ Use HKDF to derive a key from input data """
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=b'',
                info=b'', backend=default_backend())
    return hkdf.derive(inp)

def pad(msg):
    """ PKCS7 padding for AES encryption """
    num = 16 - (len(msg) % 16)
    return msg + bytes([num] * num)

def unpad(msg):
    """ Remove PKCS7 padding """
    return msg[:-msg[-1]]

class SymmRatchet:
    """ Symmetric ratchet implementation """
    def __init__(self, key):
        self.state = key

    def next(self, inp=b''):
        """ Turn the ratchet and produce a new key and IV """
        output = hkdf(self.state + inp, 80)
        self.state = output[:32]  # New state for next round
        outkey, iv = output[32:64], output[64:]  # Derived key and IV
        return outkey, iv

class Alice:
    def __init__(self):
        """ Initialize Alice's keys and ratchets """
        self.IKa = X25519PrivateKey.generate()  # Identity Key
        self.EKa = X25519PrivateKey.generate()  # Ephemeral Key
        self.DHratchet = None  # DH ratchet starts uninitialized

    def x3dh(self, bob):
        """ Perform X3DH key exchange with Bob """
        dh1 = self.IKa.exchange(bob.SPKb.public_key())
        dh2 = self.EKa.exchange(bob.IKb.public_key())
        dh3 = self.EKa.exchange(bob.SPKb.public_key())
        dh4 = self.EKa.exchange(bob.OPKb.public_key())
        self.sk = hkdf(dh1 + dh2 + dh3 + dh4, 32)
        print('[Alice]\tShared key:', b64(self.sk))

    def init_ratchets(self):
        """ Initialize symmetric ratchets using the shared key """
        self.root_ratchet = SymmRatchet(self.sk)
        self.send_ratchet = SymmRatchet(self.root_ratchet.next()[0])
        self.recv_ratchet = SymmRatchet(self.root_ratchet.next()[0])

    def dh_ratchet(self, bob_public):
        """ Perform a DH ratchet rotation using Bob's public key """
        if self.DHratchet:
            dh_recv = self.DHratchet.exchange(bob_public)
            shared_recv = self.root_ratchet.next(dh_recv)[0]
            self.recv_ratchet = SymmRatchet(shared_recv)
            print('[Alice]\tRecv ratchet seed:', b64(shared_recv))
        self.DHratchet = X25519PrivateKey.generate()
        dh_send = self.DHratchet.exchange(bob_public)
        shared_send = self.root_ratchet.next(dh_send)[0]
        self.send_ratchet = SymmRatchet(shared_send)
        print('[Alice]\tSend ratchet seed:', b64(shared_send))

    def send(self, bob, msg):
        """ Encrypt and send a message to Bob """
        key, iv = self.send_ratchet.next()
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg))
        print('[Alice]\tSending ciphertext to Bob:', b64(cipher))
        bob.recv(cipher, self.DHratchet.public_key())

    def recv(self, cipher, bob_public):
        """ Decrypt a message received from Bob """
        self.dh_ratchet(bob_public)
        key, iv = self.recv_ratchet.next()
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cipher))
        print('[Alice]\tDecrypted message:', msg.decode('utf-8'))

class Bob:
    def __init__(self):
        """ Initialize Bob's keys and ratchets """
        self.IKb = X25519PrivateKey.generate()  # Identity Key
        self.SPKb = X25519PrivateKey.generate()  # Signed PreKey
        self.OPKb = X25519PrivateKey.generate()  # One-Time PreKey
        self.DHratchet = X25519PrivateKey.generate()

    def x3dh(self, alice):
        """ Perform X3DH key exchange with Alice """
        dh1 = self.SPKb.exchange(alice.IKa.public_key())
        dh2 = self.IKb.exchange(alice.EKa.public_key())
        dh3 = self.SPKb.exchange(alice.EKa.public_key())
        dh4 = self.OPKb.exchange(alice.EKa.public_key())
        self.sk = hkdf(dh1 + dh2 + dh3 + dh4, 32)
        print('[Bob]\tShared key:', b64(self.sk))

    def init_ratchets(self):
        """ Initialize symmetric ratchets using the shared key """
        self.root_ratchet = SymmRatchet(self.sk)
        self.recv_ratchet = SymmRatchet(self.root_ratchet.next()[0])
        self.send_ratchet = SymmRatchet(self.root_ratchet.next()[0])

    def dh_ratchet(self, alice_public):
        """ Perform a DH ratchet rotation using Alice's public key """
        dh_recv = self.DHratchet.exchange(alice_public)
        shared_recv = self.root_ratchet.next(dh_recv)[0]
        self.recv_ratchet = SymmRatchet(shared_recv)
        print('[Bob]\tRecv ratchet seed:', b64(shared_recv))
        self.DHratchet = X25519PrivateKey.generate()
        dh_send = self.DHratchet.exchange(alice_public)
        shared_send = self.root_ratchet.next(dh_send)[0]
        self.send_ratchet = SymmRatchet(shared_send)
        print('[Bob]\tSend ratchet seed:', b64(shared_send))

    def send(self, alice, msg):
        """ Encrypt and send a message to Alice """
        key, iv = self.send_ratchet.next()
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(msg))
        print('[Bob]\tSending ciphertext to Alice:', b64(cipher))
        alice.recv(cipher, self.DHratchet.public_key())

    def recv(self, cipher, alice_public):
        """ Decrypt a message received from Alice """
        self.dh_ratchet(alice_public)
        key, iv = self.recv_ratchet.next()
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cipher))
        print('[Bob]\tDecrypted message:', msg.decode('utf-8'))


alice = Alice()
bob = Bob()


alice.x3dh(bob)
bob.x3dh(alice)


alice.init_ratchets()
bob.init_ratchets()


alice.dh_ratchet(bob.DHratchet.public_key())


alice.send(bob, b'Hello Bob!')
bob.send(alice, b'Hello Alice! How are you?')
alice.send(bob, b'All good, thanks!')
