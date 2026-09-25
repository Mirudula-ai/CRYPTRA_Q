def message_to_binary(message):

    return ''.join(format(ord(c),'08b') for c in message)

def binary_to_text(binary):

    chars=[]

    for i in range(0,len(binary),8):
        byte=binary[i:i+8]
        chars.append(chr(int(byte,2)))

    return ''.join(chars)

def encrypt(message,key):

    binary_msg=message_to_binary(message)

    expanded_key=(key*(len(binary_msg)//len(key)+1))[:len(binary_msg)]

    cipher=""

    for m,k in zip(binary_msg,expanded_key):
        cipher+=str(int(m)^int(k))

    return cipher

def decrypt(cipher,key):

    expanded_key=(key*(len(cipher)//len(key)+1))[:len(cipher)]

    binary=""

    for c,k in zip(cipher,expanded_key):
        binary+=str(int(c)^int(k))

    return binary_to_text(binary)