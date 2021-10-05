#!/bin/python3

#Author: Abdullah Ansari

import sys, os, argparse, hashlib, time

parser = argparse.ArgumentParser(description='three-pronged hash cracking tool')

parser.add_argument('--hashlist', dest='_hashlist',type=str, help='hash file path')
parser.add_argument('--dict', dest='_dictionary', type=str, help ='dictionary file path')
parser.add_argument('--type', dest='_hash_type',type=str, help='hash type (md5, sha1, sha256)')

args = parser.parse_args()

hashlist = args._hashlist
dictionary = args._dictionary
hash_type = str(args._hash_type).strip()

if os.path.exists('cracked_hashes.txt'):

		print('\n[-] Please remove the cracked_hashes.txt file before execution!')

		exit()

if hash_type == 'None' or hashlist is None or dictionary is None:

	print("\n[-] You must pass a hashlist, dictionary, and hash type!")

	exit()

if os.path.exists(hashlist) and os.path.exists(dictionary):

	h = open(hashlist, 'r')
	w = open (dictionary, 'r', encoding='latin-1')

	hashes_imported = len(h.readlines())
	passwords_imported = len(w.readlines())

	print(f'\n[*] {hashes_imported} hashes and {passwords_imported} passwords have been imported!')

else:

	print('\n[-] Could not find hash/dictionary files!')

	exit()

if True:

	attempt = 0
	hash_number = 1
	
	def checker(htype, target_hash, password):

		passwd = password
		encoded_passwd = passwd.encode('latin-1')
		final_passwd = encoded_passwd
		
		if htype == 'md5':

			hashed_passwd = hashlib.md5(final_passwd).hexdigest() 

		elif htype == 'sha1':

			hashed_passwd = hashlib.sha1(final_passwd).hexdigest()

		elif htype == 'sha256':

			hashed_passwd = hashlib.sha256(final_passwd).hexdigest()

		else:

			print('[-] Your hash type is not supported!')

			exit()

		if target_hash == hashed_passwd:

			return True
		
		else:

			return False

	print(f'\n[*] Hash mode set to: {hash_type}')
	print('\n[+] Starting dictionary attack!\n')

	time.sleep(1)

	print('[*] Attack in progress...\n')

	with open(hashlist, 'r') as working_hashes:

		for every_hash in working_hashes:

			every_hash = every_hash.strip('\n').lower()

			attempt = 0

			with open(dictionary, 'r', encoding='latin-1') as working_pass:

				for every_pass in working_pass:

					every_pass = every_pass.strip('\n')

					if checker(hash_type, every_hash, every_pass) == False:

						attempt+=1

						#print(f'\n[ATTEMPT {attempt}] [FAILURE] {every_hash}:{every_pass}')


					else:

						attempt+=1

						print(f'[HASH#{hash_number} CRACKED] {every_hash}:{every_pass}')

						open(f'cracked_hashes.txt', 'a+').write(f'\nHash #:		{hash_number}\nType:		{hash_type}\nOriginal:	{every_hash}\nPlaintext:	{every_pass}\nAttempt #:	{attempt}\nDictionary:	{dictionary}\n')

						hash_number+=1
						
						break

	if os.path.exists('cracked_hashes.txt'):

		print('\n[+] Plaintext credentials saved to cracked_hashes.txt!')

	else:

		print('[-] Your dictionary did not contain the password!')
