## Project Structure:

├── client.py  
├── server.py  
└── README.md

## Documentation Available At:

https://erod4.github.io/Socket-Program/

## Instructions to Run the Application:

1. Enter virtual environment:
   python3 -m venv venv1
   source venv1/bin/activate
2. Install Dependencies:
   pip install pycryptodome
3. For Client run:
   python3 Client.py
4. For Server run:
   python3 Server.py

## Summary of Cryptographic Design Choices

1. RSA for key exchange:
   RSA is used for securely exchanging the AES key between the client and server.

   RSA is asymmetric encryption, thus using two keys, a public key for encryption and a private key for decryption

   The client generates an RSA key pair and send the public key to the server

   The server generates a random AES key and crypts it using the client's public RSA key then sends the encrypted AES key back to the client

   This ensures only the respective client with the correct AES key can decrypt the message using the clients private RSA key.

2. AES for message ecnryption:L
   AES is used for the actual encryption of messages due to the speed and efficienty of the standard.

   AES is a symmetric encryption, thus using the same key for both encryption and decryption

   After the RSA handshake between a client and the server, both the client and server share the same AES key which is then used to encrypt and decrypt chat messages.

   AES-GCM is used to provide both encryption and message integrity thus ensuring that the message hasn't been tampered with during the transmission.

## Asumptions:

1. Trusted Environment: The system presupposes a trusted environment for key management. The private RSA keys must never be revealed, and client and server need to securely handle keys.

2. No Man-in-the-Middle Attacks: This implementation assumed that there are no attacks occurring during key exchange. In a real-world scenario, you would have to incorporate additional mechanisms (certificate verification or Diffie-Hellman key exchange) to prevent MITM attacks.

3. Secure Key Storage: We presume that the private keys are securely stored and are not accessible to unauthorized individuals.
