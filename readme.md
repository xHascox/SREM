# Simple RSA Messenger

## What does it do?

This program allows to encrypt text with a public key and decrypt ciphertext with a private key, therefore granting confidentiality. There are no signatures involved right now. The program also allows to create, import and export RSA keys. (4096 bit keys)

## How to:

### First Time:

Press *Generate Private Key*

Press *Generate Public Key* this can take 5-60 seconds.

Send the Public Key to the Person you want to communicate with. (Copy the Key out of the text field or use *Store Public Key* to save it to a file)

The Person you want to communicate with has to send her Public Key to you, then you have to import it by either pasting it in the upper right text field and pressing the right *Update Pasted Key* Button, or press *Load Public Key* and select the received Public Key File if you got it as a file.

_If it's not your first time, just import both your Private Key and your Communication Partners Public Key_

### Now you are ready to communicate:

*Send messages:* Type your message in the bottom left and press _Encrypt with Public Key_ and send the content of the bottom right text field to your communication partner.

*Receive messages:* Paste the received message into the bottom right text field and press _Decrypt with Private Key_ and you can read the decrypted message in the bottom left text field.


## What does what?

Generate Private Key: Generates a new RSA Private Key and stores it in the upper left text field. 

Load Private Key: Loads an RSA Private Key from a File and stores it in the upper left text field.

Store Private Key: Saves the Private Key to a file.

Update Pasted Key: You need to press this Button after you pasted (Ctrl + V) a Private Key into the upper left text field.

---

Update Pasted Key: You need to press this Button after you pasted (Ctrl + V) a Public Key into the upper right text field.

Store Public Key: Saves the Public Key to a file.

Load Public Key: Loads an RSA Public Key from a File and stores it in the upper right text field.

Generate Public Key: Derives a new RSA Public Key from the Private Key on the left side and stores it in the upper right text field. 

---

Encrypt with Public Key: Encrypts the text in the bottom left text field using the Public Key on the upper right, and stores the result in the bottom right text field.

Decrypt with Private Key: Decrypts the text in the bottom right text field using the Private Key on th eupper left, and stores the result in the bottom left text field.

## License: 
All rights belong to me except for all parts of pycryptodome which are under the BSD license.

All direct contributions to PyCryptodome are released under the following license. The copyright of each piece belongs to the respective author.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

- Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

- Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.