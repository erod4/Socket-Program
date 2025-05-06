import socket
import base64
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher    import PKCS1_OAEP, AES
from Crypto.Random    import get_random_bytes


SERVER_IP_ADDR  =   "0.0.0.0"               #Server IP Address (Bind to all interfaces)
SERVER_PORT     =   12347                   #Communication port 
BUFFER_SIZE     =   1024                    #Size of the data chunks received 2kB

IPV4            =   socket.AF_INET
UDP             =   socket.SOCK_DGRAM

clients         =   {}                       #A dictionary to hold client addresses and keys


def init_server():
    '''
    Creates UDP socket
    Binds to the specified IP port to make server accessible 
    '''
    sock=socket.socket(IPV4,UDP)
    sock.bind((SERVER_IP_ADDR,SERVER_PORT))
    print(f"{datetime.now()} - Server started on {SERVER_IP_ADDR}: {SERVER_PORT}")

    msg=None
    addr=None
    while True:
        try:
            msg, addr = sock.recvfrom(BUFFER_SIZE)  #Unpack msg, and address from client 
            
        except Exception as e:
            print(f"{datetime.now()} - Server Error: {e}")
            continue
        
        #if message starts with "PUBKEY:" it indicates a pub key handhsake from a client
        if msg.startswith(b"PUBKEY:"):
            handle_pubkey(msg[len(b"PUBKEY:"):],addr,sock)

        #if the msg starts with "ENCMSG:" the msg is an encrypted msg from the client
        elif msg.startswith(b"ENCMSG:"):
            handle_encrypted(msg[len(b"ENCMSG:"):],addr,sock)
        else:
            continue


def handle_pubkey(key, addr, sock):

    '''AES is a symmetric encryption algorithm, 
    which means it uses the same key for both 
    encryption and decryption. The same key that 
    is used to encrypt data is required to decrypt it.'''
    public_key=base64.b64decode(key)        #decode public key sent by the client
    client_rsa=RSA.import_key(public_key)   #import the public key into RSA
    rsa_cipher=PKCS1_OAEP.new(client_rsa)   #create an RSA cipher

    aes_key=get_random_bytes(32)            #generate a  random 32-Byte AES key

    encrypted_aes=rsa_cipher.encrypt(aes_key)   #encrypt AES key with users public key

    packet=b"AESKEY:"+base64.b64encode(encrypted_aes)   #prepare the packet
    sock.sendto(packet,addr)                            #send back to client

    clients[addr]=aes_key                               #store AES key for client


    print(f"{datetime.now()} - {addr} handshake complete, AES key established.")


def handle_encrypted(msg, addr, sock):
    if addr not in clients:
        print(f"{datetime.now()} - Unknown client {addr}")
        return
    
    
    aes_key= clients[addr]      #retrieve AES key for the client

    blob=base64.b64decode(msg)  #decode the encrypted message
    nonce, ct, tag = blob[:12], blob[12:-16],blob[-16:] #split the blob into nonce, ciphertext, and tag

    try:
        cipher =AES.new(aes_key,AES.MODE_GCM,nonce=nonce)   #init the AES cipher for decryption
        plain_text=cipher.decrypt_and_verify(ct, tag)       #decrypt and verify the message
    except Exception as e:
        print(f"{datetime.now()} - Decryption & Authentication failed")
        return 
    
    #broadcast message to everyone else
    broadcast_msg(sock, plain_text, excl_addr=addr)


def broadcast_msg(sock, msg, excl_addr=None):
    '''
    
    '''
    #loop through clients and retrieve address and key, encode msg and broadcast to clients
    for addr, key in clients.items():
        if addr==excl_addr:
            continue            #skip sending client

        nonce = get_random_bytes(12)    #generate a random nonce for encryption
        cipher = AES.new(key, AES.MODE_GCM,nonce=nonce) #encrypt the msg with AES
        ct, tag = cipher.encrypt_and_digest(msg)    #encrypt the message and generate tag
        
        #format packet
        packet = b"ENCMSG:"+base64.b64encode(nonce+ct+tag)

        try:
            #send packet to client
            sock.sendto(packet,addr)
        except Exception as e:
            print(f"{datetime.now()} - Broadcast to {addr} failed: {e}")

if __name__=="__main__":
        init_server()