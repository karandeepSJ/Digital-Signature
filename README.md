# Digital Signature Using DLP
Build a digital signature scheme using the Discrete Logarithm Problem(DLP) and
hash functions. Design the collision-resistant hash functions also using DLP.

# Scheme
The detailed signature scheme and proof of correctness is given in [Digital Signatures](./Digital%20Signatures.pdf)

# Implementation
The code does not establish any actual connection between the signer and verifier. The ciphertext is simply stored in a variable, which the verifier takes as a parameter.    
- Libraries Used: 
	- Crypto - To generate large prime
	- random
	- math

# Running The Code
After installing all the libraries, simply run 
`python signature.py`
This will ask for the signer's private key and message to sign as inputs, perform the signature protocol, print it, and then verify the signature.


