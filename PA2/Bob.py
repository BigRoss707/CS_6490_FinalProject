import sys, socket, uuid, hashlib, hmac, time, subprocess, os
from Crypto.Cipher import AES, DES
from M2Crypto import RSA, X509, EVP, BIO


#output file for Bob
f = open('Bob_out.txt', 'w')

server_socket = 10000

#load certificate
certificate = open('Bob.crt').read()

#load private key
pk = open('Bob.key').read()
bio = BIO.MemoryBuffer(pk)
key = RSA.load_key_bio(bio)

#create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#bind socket to port
server_address = ('localhost', server_socket)
sock.bind(server_address)

f.write('[Bob]: Listening on %s: %s\n' %server_address)

#listen for incoming connections
sock.listen(1)

while True:
	#wait for a connection
	
	#accept a connection
	connection, client_address = sock.accept()

	#receive client hello message
	client_hello = connection.recv(900)

	#check that its a hello from client
	if 'I want to talk' in client_hello:
		f.write('[Bob]: Received client hello msg\n')
	else:
		f.write('[Bob]: Invalid message. Aborting connection....\n')
		continue

	#extract encyption method
	i = len('I want to talk')
	encryption_method = client_hello[i:i+3]

	#extract ceritificate from message public key from ceritificate
	c_i = i + 3
	cert_alice = X509.load_cert_string(client_hello[c_i:], X509.FORMAT_PEM)

	#verify certificate that it is signed by CA
	f_crt = open('Rcv_cert_from_Alice.crt', 'w')
	f_crt.write(client_hello[c_i:])
	f_crt.close()
	p = subprocess.Popen(["openssl verify -CAfile rootCA.pem Rcv_cert_from_Alice.crt"], stdout=subprocess.PIPE, shell=True)
	result = p.stdout.read()
	if 'Rcv_cert_from_Alice.crt: OK' in result:
		f.write('[Bob]: Certificate received from Alice is OK\n')
	else:
		f.write('[Bob]: Certificate received from Alice is not signed by rootCA. Aborting connection...\n')
		print('[Bob]: Certificate received from Alice is not signed by rootCA. Aborting connection...\n')
		sys.exit(1)

	#extract public key from ceritificate
	pub_key_alice = cert_alice.get_pubkey()
	rsa_key_alice = pub_key_alice.get_rsa()

	#generate nonce R_bob(32 bit)
	R_bob = uuid.uuid4().get_hex()
	f.write('[Bob]: Generated R_bob = %s\n'%R_bob)

	#send server hello message
	server_hello = certificate + rsa_key_alice.public_encrypt(R_bob, RSA.pkcs1_padding)
	f.write('[Bob]: Sent server hello message.\n')

	connection.sendall(server_hello)

	#receive R_alice
	R_alice_msg = connection.recv(200)
	R_alice = key.private_decrypt(R_alice_msg, RSA.pkcs1_padding)
	f.write('[Bob]: Received R_alice = %s\n'%R_alice)

	#calculate master secret
	master_secret = int(R_bob, 16) ^ int(R_alice, 16)
	master_secret = '{:x}'.format(master_secret)

	#receive hash
	hash_alice = connection.recv(200)
	all_msg = client_hello + server_hello + R_alice_msg

	#check received hash
	all_msg_hmac_cl =  hmac.new(master_secret, all_msg+'CLIENT', hashlib.sha1).hexdigest()

	if hash_alice == all_msg_hmac_cl:
		f.write('[Bob]: Received hash matched\n')
	else:
		f.write('[Bob]: Received hash did not match. Aborting connection...\n')
		print('[Bob]: Received hash did not match. Aborting connection...\n')
		continue

	#send keyed hash of handshake messages
	connection.sendall(hmac.new(master_secret, all_msg+'SERVER', hashlib.sha1).hexdigest())


	#generate keys
	if encryption_method == 'CBC':
		enc_key_alice = AES.new(master_secret, AES.MODE_CBC, '0000000000000000')
		enc_key_bob= AES.new(master_secret, AES.MODE_CBC, '0000000000001111')
	elif encryption_method == 'ECB':
		enc_key_alice = DES.new(master_secret[:8], DES.MODE_ECB)
		enc_key_bob= DES.new(master_secret[8:16], DES.MODE_ECB)

	intr_key_alice = master_secret + 'alice'
	intr_key_bob= master_secret + 'bob'

	#receive data and decrypt
	data_msg = connection.recv(800000)
	header = data_msg[:4+1+4] 
	l = int(header[-4:], 16)

	decrypt = enc_key_alice.decrypt(data_msg[4+1+4:])
	data = decrypt[:l]
	data_hmac = decrypt[l:l+40]

	cal_hmac = hmac.new(intr_key_alice, '0' + header + data, hashlib.sha1).hexdigest()

	if(data_hmac == cal_hmac):
		f.write('[Bob]: HMAC of received data matched\n')
	else:
		f.write('[Bob]: HMAC of received data did not match. Discarding received data....\n')

	#save received data in a file
	out = open('file_rcv.txt','w')
	out.write(data)
	break
