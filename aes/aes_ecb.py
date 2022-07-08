from Crypto.Cipher import AES

obj = AES.new("This is a key 123", AES.MODE_CBC, "asdlkajdf")

message = "operachromeie"

ciphertext = obj.encrypt(message)


print(ciphertext)
