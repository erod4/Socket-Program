import socket, os, base64,threading
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher    import PKCS1_OAEP, AES
from Crypto.Random    import get_random_bytes

IPV4            =   socket.AF_INET
UDP             =   socket.SOCK_DGRAM

SERVER_IP_ADDR  =   '0.0.0.0'  # Bind to all interfaces
SERVER_PORT     =   12347
BUFFER_SIZE     =   1024
#generate RSA key pair [priv key,public key]
key             =   RSA.generate(2048)
private_key     =   key
public_key      =   key.publickey().export_key(format='PEM')




def init_client(username):


    print("Establishing Secure Connection...")
    sock=socket.socket(IPV4, UDP)

    #send pub key handshake to server
    encoded_public_key=base64.b64encode(public_key)
    #send public key as a bytes object for UDP
    sock.sendto(b"PUBKEY:"+encoded_public_key,(SERVER_IP_ADDR,SERVER_PORT))
    aes_key=None
    while True:
        try: 
            data,_=sock.recvfrom(BUFFER_SIZE)   # read from buffer 
        except BlockingIOError:
            continue
        if not data.startswith(b"AESKEY:"):     #if key isnt provided for server keep waiting
            continue

        aes_key=data.split(b":")[1]
        aes_encrypted=base64.b64decode(aes_key)

        #decrypt AES key with RSA OAEP
        rsa_cipher=PKCS1_OAEP.new(private_key)
        aes_key=rsa_cipher.decrypt(aes_encrypted)
        print(f"Secure Connection Established. Welcome {username}.")

        #enter chat application
        break   
    threading.Thread(target=receive_messages,args=(aes_key, sock),daemon=True).start()
    while True:
        try:
            msg=input("Message: ")

            #encrypt message
            nonce   =   get_random_bytes(12)
            cipher  =   AES.new(aes_key,AES.MODE_GCM, nonce=nonce)
            ct, tag =   cipher.encrypt_and_digest((f"{username}: {msg}").encode())
            packet  =   b"ENCMSG:"+base64.b64encode(nonce+ct+tag)

            #send encrypted message
            sock.sendto(packet,(SERVER_IP_ADDR,SERVER_PORT))
        except Exception as e:
            print(f"{datetime.now()} - Client Error: {e}")

def receive_messages(aes_key,sock):
    aes=aes_key
    while True:
        try:
            data,addr=sock.recvfrom(BUFFER_SIZE)
        except Exception as e:
            print(f"{datetime.now()} - Message Receipt Error: {e}")
            return

        if not data.startswith(b"ENCMSG:"):  #only allowed to receive encrypted data
            continue

        try:
            blob = base64.b64decode(data[len(b"ENCMSG:"):])
        except Exception as e:
            print(f"{datetime.now()} - Invalid base64 from {addr}: {e}")
            continue

        nonce, ct, tag =blob[:12], blob[12:-16], blob[-16:]
        cipher=AES.new(aes, AES.MODE_GCM, nonce=nonce)

        #decrypt packet and throw error if failure occurs
        pt=None
        try:
            pt=cipher.decrypt_and_verify(ct,tag).decode()
        except ValueError:
            print(f"{datetime.now()} - Auth Failed: {ValueError}")
        print(f"\n {pt}")
        print("Message: ", end="",flush=True)

if __name__=="__main__":
    user=input("Enter Username: ").strip()
    init_client(user)