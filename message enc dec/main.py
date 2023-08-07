from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import cryptography
import base64
import os
def main_menu():
    print("Welcome to the Encryption/Decryption Tool!")
    print("Choose an option:")
    print("1. Encrypt a message")
    print("2. Decrypt a message")
    print("3. Exit")

    while True:
        choice = input("Enter your choice (1-3): ")

        if choice == '1':
            encrypt_message()
        elif choice == '2':
            decrypt_message()
        elif choice == '3':
            print("Exiting the Encryption/Decryption Tool. Goodbye!")
            exit()
        else:
            print("Invalid choice. Please try again.")

def Rsa_encrypt():
    # Generate an RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # Prompt the user for the message to encrypt
    message = input("Enter the message to encrypt: ")

    # Encrypt the message using the recipient's public key
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )

    # Create a 'keys' directory if it doesn't exist
    keys_dir = "keys"
    if not os.path.exists(keys_dir):
        os.makedirs(keys_dir)

    # Prompt the user for the initial name of the public and private key files
    public_key_name = input("Enter the initial name for the public key file (without extension): ")
    private_key_name = input("Enter the initial name for the private key file (without extension): ")

    # Save the public key to a file in the 'keys' directory
    public_key_file = os.path.join(keys_dir, f"{public_key_name}.pub")
    with open(public_key_file, 'wb') as file:
        file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        print(f"Public key saved to {public_key_file}")

    # Save the private key to a file in the 'keys' directory
    private_key_file = os.path.join(keys_dir, f"{private_key_name}.private")
    with open(private_key_file, 'wb') as file:
        file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
        print(f"Private key saved to {private_key_file}")

    # Create an 'enc_message' directory if it doesn't exist
    enc_message_dir = "enc_message"
    if not os.path.exists(enc_message_dir):
        os.makedirs(enc_message_dir)

    # Prompt the user for the name of the file to save the encrypted message
    enc_message_name = input("Enter the name of the file to save the encrypted message (without extension): ")

    # Save the encrypted message to a file inside the 'enc_message' directory
    enc_message_file = os.path.join(enc_message_dir, f"{enc_message_name}.enc")
    with open(enc_message_file, 'wb') as file:
        file.write(ciphertext)
        print(f"Encrypted message saved to {enc_message_file}")

    # Display the encrypted message
    print("\nEncrypted Message (Asymmetric - RSA):")
    print(ciphertext.hex())
    main_menu()

def symm_encrypt():
    # Prompt the user for the message to encrypt
    message = input("Enter the message to encrypt: ")

    # Prompt the user for the encryption password
    password = input("Enter the encryption password: ")

    # Generate a salt for the key derivation
    salt = b'salt_'

    # Derive a key from the provided password using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    key = kdf.derive(password.encode())

    # Create a Fernet symmetric encryption object using the derived key
    fernet = Fernet(base64.urlsafe_b64encode(key))

    # Encrypt the message using the Fernet encryption object
    ciphertext = fernet.encrypt(message.encode())

    # Prompt the user for the filename to save the encrypted message
    filename = input("Enter the filename to save the encrypted message: ")

    # Save the encrypted message to a file
    with open(f"enc_message/{filename}.enc", "w") as file:
        file.write(ciphertext.decode())

    # Display the success message
    print(f"\nEncrypted message saved to enc_message/{filename}.enc")
    main_menu()

def rsa_decrypt():
    # Prompt the user for the path to the encrypted message file
    filepath = input("Enter the path to the encrypted message file: ")

    # Prompt the user for the path to the private key file
    private_key_path = input("Enter the path to the private key file: ")

    try:
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )

        with open(filepath, "rb") as encrypted_file:
            encrypted_message = encrypted_file.read()

        decrypted_message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Prompt the user for the filename to save the decrypted message
        filename = input("Enter the filename to save the decrypted message: ")

        # Create the 'message' folder if it doesn't exist
        if not os.path.exists("message"):
            os.makedirs("message")

        # Save the decrypted message to a file inside the 'message' folder
        with open(f"message/{filename}.txt", "w") as file:
            file.write(decrypted_message.decode())

        # Display the success message
        print(f"\nDecrypted message saved to message/{filename}.txt")

    except FileNotFoundError:
        print("File not found. Please check the file path.")
        rsa_decrypt()

    except ValueError:
        print("Invalid private key file. Please check the key file format.")
        rsa_decrypt()

    except cryptography.exceptions.UnsupportedAlgorithm:
        print("Unsupported algorithm used in private key. Please check the key file.")
        rsa_decrypt()

    except cryptography.exceptions.InvalidSignature:
        print("Invalid private key. Decryption failed.")
        rsa_decrypt()

    except cryptography.exceptions.CryptoError:
        print("Decryption error occurred. Please check the encryption method.")
        rsa_decrypt()

    except Exception as e:
        print("An error occurred during decryption:", str(e))
        rsa_decrypt()
    main_menu()
    
def symm_decrypt():
    # Prompt the user for the path to the encrypted message file
    filepath = input("Enter the path to the encrypted message file: ")

    # Prompt the user for the encryption password
    password = input("Enter the encryption password: ")

    try:
        # Read the encrypted message from the file
        with open(filepath, "r") as encrypted_file:
            ciphertext = encrypted_file.read()

        # Generate a salt for the key derivation
        salt = b'salt_'

        # Derive the key from the provided password using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        key = kdf.derive(password.encode())

        # Create a Fernet symmetric encryption object using the derived key
        fernet = Fernet(base64.urlsafe_b64encode(key))

        # Decrypt the message using the Fernet encryption object
        decrypted_message = fernet.decrypt(ciphertext.encode())

        # Prompt the user for the filename to save the decrypted message
        filename = input("Enter the filename to save the decrypted message: ")

        # Save the decrypted message to a file
        with open(f"message/{filename}.txt", "w") as file:
            file.write(decrypted_message.decode())

        # Display the success message
        print(f"\nDecrypted message saved to message/{filename}.txt")

    except FileNotFoundError:
        print("File not found. Please check the file path.")

    except cryptography.fernet.InvalidToken:
        print("Invalid encryption password or encrypted message. Decryption failed.")

    except Exception as e:
        print("An error occurred during decryption:", str(e))


def encrypt_message():
    print("\nEncryption Mode Selected")

    # Prompt the user for the encryption method and mode
    encryption_method = input("Choose encryption method (1: Asymmetric, 2: Symmetric): ")

    if encryption_method == '1':
        print("\nAsymmetric Encryption Selected")
        print("Starting RSA Encryption...")
        Rsa_encrypt()
    elif encryption_method == '2':
        print("\nSymmetric Encryption Selected")
        print("Starting AES Symmetric Encryption...")
        symm_encrypt()
    else:
        print("Invalid encryption method. Please try again.")

def decrypt_message():
    print("\nDecryption Mode Selected")

    # Prompt the user for the decryption method and mode
    decryption_method = input("Choose decryption method (1: Asymmetric, 2: Symmetric): ")

    if decryption_method == '1':
        print("\nAsymmetric Decryption Selected")
        print("Starting RSA Decryption...")
        rsa_decrypt()
    elif decryption_method == '2':
        print("\nSymmetric Decryption Selected")
        print("Starting AES Symmetric Decryption...")
        symm_decrypt()
    else:
        print("Invalid decryption method. Please try again.")

if __name__ == '__main__':
    main_menu()
