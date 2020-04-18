import sys, os, socket, uuid, hashlib, hmac, time, subprocess
from Crypto.Cipher import AES, DES
from M2Crypto import RSA, X509, EVP, BIO

#output file for Alice
f = open('Alice_out.txt', 'w')
server_socket = 10000

#load certificate
certificate = open('Alice.crt').read()

#load private key
pk = open('Alice.key').read()
bio = BIO.MemoryBuffer(pk)
key = RSA.load_key_bio(bio)

#encryption method
encryption_method = 'ECB' #can change it to CBC

#create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#connect socket to the port where the server is listening
server_address = ('localhost', server_socket)
print('Connecting to Bob..')
f.write('[Alice]: Connecting to bob on %s: %s\n' % server_address)
sock.connect(server_address)

#send client hello message to server
client_hello = 'I want to talk' + encryption_method + certificate
f.write('[Alice]: Sent client hello msg to Bob(server)\n')
sock.sendall(client_hello)

server_hello = sock.recv(1000)

#extract certificate from server hello
cert_bob = X509.load_cert_string(server_hello[:-128], X509.FORMAT_PEM)

#verify certificate that it is signed by CA
f_crt = open('Rcv_cert_from_bob.crt', 'w')
f_crt.write(server_hello[:-128])
f_crt.close()
p = subprocess.Popen(["openssl verify -CAfile rootCA.pem Rcv_cert_from_bob.crt"], stdout=subprocess.PIPE, shell=True)
result = p.stdout.read()
if 'Rcv_cert_from_bob.crt: OK' in result:

	f.write('[Alice]: Certificate received from Bob is verfied\n')
else:
	f.write('[Alice]: Certificate received from Bob is not signed by rootCA. Aborting connection...\n')
	print('[Alice]: Certificate received from Bob is not signed by rootCA. Aborting connection...\n')
	sys.exit(1)


#extract public key from ceritificate
pub_key_bob = cert_bob.get_pubkey()
rsa_key_bob = pub_key_bob.get_rsa()

#extract R_bob
R_bob = key.private_decrypt(server_hello[-128:], RSA.pkcs1_padding)
f.write('[Alice]: Received R_bob = %s\n'%R_bob)

#generate nonce R_alice (32 bit)
R_alice = uuid.uuid4().get_hex()
f.write('[Alice]: Generated R_alice = %s\n'%R_alice)

#send R_alice
R_alice_msg = rsa_key_bob.public_encrypt(R_alice, RSA.pkcs1_padding)
sock.sendall(R_alice_msg)

#calculate master secret
master_secret = int(R_bob, 16) ^ int(R_alice, 16)
master_secret = '{:x}'.format(master_secret)


#send keyed hash of handshake messages
all_msg = client_hello + server_hello + R_alice_msg
all_msg_hmac =  hmac.new(master_secret, all_msg + 'CLIENT', hashlib.sha1).hexdigest()
f.write('[Alice]: Sent keyed hash of handshake messages\n')

sock.sendall(all_msg_hmac)

#receive keyed hash of handshake messages
hash_bob = sock.recv(200)

#check received hash
all_msg_hmac_svr =  hmac.new(master_secret, all_msg+'SERVER', hashlib.sha1).hexdigest()

if hash_bob == all_msg_hmac_svr:
    f.write('[Alice]: Received hash matched\n')
else:
    f.write('[Alice]: Received hash did not match. Aborting connection...\n')
    print('[Alice]: Received hash did not match. Aborting connection...\n')
    sys.exit(1)


#generate keys
if encryption_method == 'CBC':
	enc_key_alice = AES.new(master_secret, AES.MODE_CBC, '0000000000000000')
	enc_key_bob = AES.new(master_secret, AES.MODE_CBC, '0000000000001111')
elif encryption_method == 'ECB':
	enc_key_alice = DES.new(master_secret[:8], DES.MODE_ECB)
	enc_key_bob = DES.new(master_secret[8:16], DES.MODE_ECB)

intr_key_alice = master_secret + 'alice'
intr_key_bob= master_secret + 'bob'

#send data
data = open('file.txt').read()
header = 'data' + '1' + hex(len(data))[2:]
hmac_record = hmac.new(intr_key_alice, '0' + header + data, hashlib.sha1).hexdigest()
l =  len(data + hmac_record)
b = l//16
pad = ''.zfill((b+1)*16 -l)
enc_record = enc_key_alice.encrypt(data + hmac_record + pad)
f.write('[Alice]: Sent file.\n')
sock.sendall(header+enc_record)

f.close()