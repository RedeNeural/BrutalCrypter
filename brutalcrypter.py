#!/usr/bin/python3

import binascii
import rsa
import os
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64decode

# Brutal Crypter
###
# Limpar tela
os.system('cls' if os.name == 'nt' else 'clear')

# Cabecalho
print "#" * 40
print "####### Brutal Security Crypter ########"
print "#" * 40

# Menu
print ""
print "Escolha uma opcao"
print "1- Criar uma chave secreta"
print "2- Cifrar arquivos"
print "3- Decifrar arquivos"
print "4- Gerar par de chaves (publica/privada)"
print "5- Cifrar a chave"
print "6- Decifrar a chave"
escolha = input("")




# Funcao para completar o bloco com o tamanho do bloco do AES
def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

# Funcao que criptografa o conteudo da variavel
def encrypt(message, key, key_size=256):
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

# Funcao que decriptografa o conteudo da variavel
def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")

# Funcao que abre o arquivo e joga para a variavel o conteudo pra criptografar
def encrypt_file(file_name, key):
    with open(file_name, 'rb') as fo:
        plaintext = fo.read()
    enc = encrypt(plaintext, key)
    with open(file_name + ".enc", 'wb') as fo:
        fo.write(enc)

# Funcao que abre o arquivo e joga para a variavel o conteudo para decriptografar
def decrypt_file(file_name, key):
    with open(file_name, 'rb') as fo:
        ciphertext = fo.read()
    dec = decrypt(ciphertext, key)
    with open(file_name[:-4], 'wb') as fo:
        fo.write(dec)

# Opcao 1 do menu, criar chave simetrica e guardar em um arquivo
def create_simkey():
    key = raw_input("Informe a senha: ")
    f = open("SimKey.key", "w")
    m = hashlib.sha256() # Mudar para criacao do AES se der tempo
    m.update(key)
    key = m.digest()
    f.write(binascii.hexlify(key))
    f.close

# Opcao 2 do menu, criptografar arquivo, funcao verifica se arquivo e chave existe e chama a funcao de criptografia
def sim_crypt():
    arquivo = raw_input("Informe o arquivo que deseja criptografar: ")
    if os.path.isfile(arquivo):
		if os.path.isfile("SimKey.key"):
			print "Chave encontrada! Iniciando criptografia..."
			with open("SimKey.key", 'rb') as fo:
				key = fo.read()
				key = binascii.unhexlify(key)
    				encrypt_file(arquivo, key)
		else:
			print "Chave nao encontrada! Primeiro voce deve criar uma chave secreta (opcao 1 no menu)..."
    else:
		print "Arquivo nao encontrado! Tente novamente..."

# Opcao 3 do menu, decriptografar arquivo, funcao verifica se arquivo e chave existe e chama a funcao de decriptografia
def sim_decrypt():
    arquivo = raw_input("Informe o arquivo que deseja decriptografar: ")
    if os.path.isfile(arquivo):
		if os.path.isfile("SimKey.key"):
			print "Chave encontrada! Iniciando criptografia..."
			with open("SimKey.key", 'rb') as fo:
				key = fo.read()
				key = binascii.unhexlify(key)
				decrypt_file(arquivo, key)
		else:
			print "Chave nao encontrada! Primeiro voce deve criar uma chave secreta (opcao 1 no menu)..."
    else:
		print "Arquivo nao encontrado! Tente novamente..."

# Opcao 4 do menu, geracao de par de chaves RSA, funcao gera o par de chaves e salva cada um em um arquivo.
def create_assim_key():
    print "Gerando par de chave assimetrica (publica/privada)..."
    private = RSA.generate(1024)
    public = private.publickey()
    with open("Pub.key", "wb") as fo:
	fo.write(public.exportKey('PEM'))
    with open("Priv.key", "wb") as fo:
	fo.write(private.exportKey('PEM'))
    print "Par de chave gerado!"

# Opcao 5 do menu, criptografia da chave simetrica com a chave publica.
def assim_crypt():
    if os.path.isfile("Pub.key"):
	print "Chave publica encontrada!"
	if os.path.isfile("SimKey.key"):
		print "Chave simetrica encontrada! Iniciando criptografia..."
		with open("SimKey.key", 'r') as fo:
			sim_key = fo.read()
		with open("Pub.key", 'r') as fo:
			pub_key = fo.read()
		aux = RSA.importKey(pub_key)
		aux = PKCS1_OAEP.new(aux)
		enc_key = aux.encrypt(sim_key)
		enc_key = enc_key.encode('base64')
		with open("Key.enc", 'wb') as fo:
			fo.write(enc_key)
	else:
		print "Chave simetrica nao encontrada! Tente novamente..."
    else:
	print "Chave publica nao encontrada! Tente novamente..."

# Opcao 6 do menu, decriptografia da chave simetrica com a chave privada.
def assim_decrypt():
    if os.path.isfile("Priv.key"):
	print "Chave privada encontrada!"
	if os.path.isfile("Key.enc"):
		print "Chave criptografada encontrada! Iniciando decriptografia..."
		with open("Priv.key", 'r') as fo:
			priv_key = fo.read()
		with open("Key.enc", 'r') as fo:
			enc_key = fo.read()
		aux = RSA.importKey(priv_key)
		aux = PKCS1_OAEP.new(aux)
		key = aux.decrypt(b64decode(enc_key))
		with open("SimKey.key", 'w') as fo:
			fo.write(key)
	else:
		print "Chave simetrica nao encontrada! Tente novamente..."
    else:
	print "Chave publica nao encontrada! Tente novamente..."

# Escolha de opcao do menu
if escolha == 1:
	create_simkey()
elif escolha == 2:
	sim_crypt()
elif escolha == 3:
	sim_decrypt()
elif escolha == 4:
	create_assim_key()
elif escolha == 5:
	assim_crypt()
elif escolha == 6:
	assim_decrypt()
else:
	print "Opcao nao exite, tente novamente!"
