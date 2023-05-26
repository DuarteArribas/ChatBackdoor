# ChatWithBackdoor

This software was designed to create an apparently secure and private chatting environment. 

Within the realm of our software, a sophisticated framework of cryptographic techniques is meticulously woven, ensuring the "utmost" protection for the conversations. By employing cutting-edge key exchange protocols, we establish a secure channel that thwarts potential eavesdroppers, preventing them from intercepting sensitive information. With locally stored cipher keys and message encryption, we shield the messages from prying eyes, making them intelligible only to their intended recipients.

Notwithstanding, the server is able to decipher every message and is able to change it and recalculate the hmac and RSA digital signature, so that the receiver does not notice that the message had been changed. This simulates a man-in-the-middle attack.

In our project we employed:

* Server and client communications with TCP sockets;
* Threading and socket management;
* Clients' synchronization;
* Chat system between registered clients;
* Key exchange using Diffie-Hellman over Elliptic Curves;
* Strong and zero-knowledge's authentication protocols, viz., CHAP and Schnorr, for register and login operations (identification & authentication);
* Friend system;
* Message ciphering and HMAC calculations using AES;
* Digital Signatures calculated using RSA;
* Password hashing with salt & pepper;
* Man-in-the-middle attack.

The project can be checked on [GitHub](https://github.com/DuarteArribas/ChatBackdoor).

## Running the project

The project is composed by two pieces of software, namely, *Server* and *Client*. After running `cd ChatWithBackdoor`, the project dependencies must be installed and the database initialized by running `make setup`.

Then, the server and client(s) may be run by running `make runServer` and `make runClient`, respectively.

Then, just follow the instructions on the programs; alternatively, you may also check the system models in order to understand the system's function. 

## Authors

The project was developed by:

* Beatriz Caldeira, M12432;
* Duarte Arribas, M12324;
* Manuel Magalhães, M12239;
* Sara Martins, E10973.

Thanks! 👉😎👈