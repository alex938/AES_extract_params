import base64
import hashlib
from Crypto.Cipher import AES

#put into variable
#echo -n "I will pass the module 6 exam" | openssl enc -aes-256-cbc -pbkdf2 -out a.enc -base64 -p 

#confirm salt value within ciphertext
#echo -n "I will pass the module 6 exam" | openssl enc -aes-256-cbc -pbkdf2 -out a.enc -p
#xxd a.enc (salt from 8 to 16 bytes)

#H(password) = ok hash (vulnerable to dictionary attacks, rainbow tables etc)
#H(salt+password) = stronger hash (however, moors law every two years, the number of transistors on microchips will double)
#H(salt+password) * no of iterations = PBKDF2 (we go for as many iterations as tolerable)

#inputs
openssloutputb64='U2FsdGVkX19Rws8lhwU4OOV6vTt6of2xVp/MaeKpF4mqO4kI4z+GLMKWZiDOsL7G'
password='test'

#10000 iterations is the default for openssl
pbkdf2iterations=10000

#convert inputs to bytes
openssloutputbytes=base64.b64decode(openssloutputb64)
passwordbytes=password.encode('utf-8')

#salt is bytes 8 through 15 of openssloutputbytes
#view hex to see Salted__{salt}
salt=openssloutputbytes[8:16]

#aes key lengths of 128, 192, or 256 bits (16 or 24 or 32 bytes) 
#derive the 48-byte key using pbkdf2 given the password and salt with 10000 iterations of sha256 hashing
derivedkey=hashlib.pbkdf2_hmac('sha256', passwordbytes, salt, pbkdf2iterations, 48)

#key is bytes 0-31 of derivedkey, iv is bytes 32-47 of derivedkey 
key=derivedkey[0:32]
#iv derived from the salt+password
iv=derivedkey[32:48]

#ciphertext is bytes 16-end of openssloutputbytes
ciphertext=openssloutputbytes[16:]

#decrypt ciphertext using aes-cbc, given key, iv, and ciphertext
decryptor=AES.new(key, AES.MODE_CBC, iv)
plaintext=decryptor.decrypt(ciphertext)

#remove PKCS#7 padding
#example of 16 byte block 

#“testing1”
#74657374696e67310808080808080808

#last byte of plaintext indicates the number of padding bytes appended to end of plaintext.  This is the number of bytes to be removed.
plaintext = plaintext[:-plaintext[-1]]

#confirm results against input
print('openssloutputb64:', openssloutputb64)
print('password:', password)
print('salt:', salt.hex())
print('key:', key.hex())
print('iv:', iv.hex())
print('ciphertext:', ciphertext.hex())
print('plaintext:', plaintext.decode('utf-8'))
