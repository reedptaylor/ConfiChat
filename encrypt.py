# EXAMPLE ENCRYPT/DECRYPT. Partially taken from stackoverflow and partially added/edited myself. only use for reference

import Crypto.Cipher.AES
import Crypto.Util.Counter

key = "0123456789ABCDEF" # replace this with a sensible value, preferably the output of a hash
iv = "0000000000009001" # replace this with a RANDOMLY GENERATED VALUE, and send this with the ciphertext!

plaintext = "Attack at dawn" # replace with your actual plaintext

ctr = Crypto.Util.Counter.new(128, initial_value=long(iv.encode("hex"), 16))

cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CTR, counter=ctr)
ciphertext = cipher.encrypt(plaintext)
print ciphertext

ctr2 = Crypto.Util.Counter.new(128, initial_value=long(iv.encode("hex"), 16))
dec = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CTR, counter=ctr2)
plaintext = dec.decrypt(ciphertext)
print plaintext
