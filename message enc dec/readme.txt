    This Python script performs encryption and decryption of messages using both asymmetric and symmetric encryption algorithms, namely AES and RSA.

    The script follows this workflow:

    1. It prompts the user to choose between encryption or decryption.
    2. Based on the user's choice, it further asks whether to use asymmetric or symmetric encryption.
    3. In asymmetric encryption, it generates a pair of public and private keys and saves them in a key file. The public key is used for encryption.
    4. In symmetric encryption, it asks for encryption keys from the user and saves the encrypted message in the enc_message file.
    5. For decryption, it asks for the private key in asymmetric encryption and encryption keys in symmetric encryption. It then decrypts the message and saves it in a message file.
    In summary, this script provides a versatile encryption/decryption tool that allows users to choose between asymmetric and symmetric encryption methods and securely encrypt and decrypt messages.