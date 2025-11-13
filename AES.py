import argparse
import getpass
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# --- CONFIGURATION ---
KEY_SIZE = 32         # 32 bytes = 256-bit key
SALT_SIZE = 16        # 16 bytes = 128-bit salt
NONCE_SIZE = 16       # 16 bytes = 128-bit nonce
TAG_SIZE = 16         # 16 bytes = 128-bit tag
ITERATIONS = 100000   # Number of PBKDF2 iterations
# ---------------------

def encrypt(password, plaintext_file, ciphertext_file):
    """
    Encrypts a file using AES-256-GCM.
    """
    try:
        # 1. Read plaintext
        with open(plaintext_file, 'rb') as f_in:
            plaintext = f_in.read()
    except FileNotFoundError:
        print(f"Error: Input file '{plaintext_file}' not found.")
        return
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    # 2. Generate a random salt
    salt = get_random_bytes(SALT_SIZE)

    # 3. Derive the encryption key from the password and salt
    key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS)

    # 4. Create a new AES cipher in GCM mode
    cipher = AES.new(key, AES.MODE_GCM)

    # 5. Get the nonce (it's generated automatically)
    nonce = cipher.nonce

    # 6. Encrypt the data and get the ciphertext and authentication tag
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    # 7. Write the [salt][nonce][tag][ciphertext] to the output file
    try:
        with open(ciphertext_file, 'wb') as f_out:
            f_out.write(salt)
            f_out.write(nonce)
            f_out.write(tag)
            f_out.write(ciphertext)
        print(f"Encryption successful! Output saved to '{ciphertext_file}'")
    except Exception as e:
        print(f"Error writing to file: {e}")

def decrypt(password, ciphertext_file, plaintext_file):
    """
    Decrypts a file encrypted with AES-256-GCM.
    """
    try:
        # 1. Read the encrypted file
        with open(ciphertext_file, 'rb') as f_in:
            data = f_in.read()
    except FileNotFoundError:
        print(f"Error: Input file '{ciphertext_file}' not found.")
        return
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    # 2. Extract the [salt][nonce][tag][ciphertext]
    # We know their sizes from our configuration
    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    tag = data[SALT_SIZE + NONCE_SIZE:SALT_SIZE + NONCE_SIZE + TAG_SIZE]
    ciphertext = data[SALT_SIZE + NONCE_SIZE + TAG_SIZE:]

    # 3. Derive the key using the *same* salt and password
    key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS)

    # 4. Create the AES cipher with the same key and nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # 5. Decrypt and VERIFY the data.
    # This will raise a ValueError if the key is wrong or the
    # data has been tampered with (tag is invalid).
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        print("Decryption failed! The key is incorrect or the file is corrupted.")
        return
    except Exception as e:
        print(f"An error occurred: {e}")
        return

    # 6. Write the decrypted plaintext to the output file
    try:
        with open(plaintext_file, 'wb') as f_out:
            f_out.write(plaintext)
        print(f"Decryption successful! Output saved to '{plaintext_file}'")
    except Exception as e:
        print(f"Error writing to file: {e}")

def main():
    parser = argparse.ArgumentParser(description="Encrypt or decrypt a file using AES-256-GCM.")
    subparsers = parser.add_subparsers(dest="mode", required=True, help="Mode: 'encrypt' or 'decrypt'")

    # --- Encrypt subcommand ---
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    encrypt_parser.add_argument("-i", "--input", required=True, help="Input file to encrypt (plaintext)")
    encrypt_parser.add_argument("-o", "--output", required=True, help="Output file to save (ciphertext)")

    # --- Decrypt subcommand ---
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    decrypt_parser.add_argument("-i", "--input", required=True, help="Input file to decrypt (ciphertext)")
    decrypt_parser.add_argument("-o", "--output", required=True, help="Output file to save (plaintext)")

    args = parser.parse_args()

    # Securely get the password from the user
    try:
        password = getpass.getpass("Enter password: ")
    except Exception as e:
        print(f"Error getting password: {e}")
        return

    # Run the correct function based on the mode
    if args.mode == "encrypt":
        encrypt(password, args.input, args.output)
    elif args.mode == "decrypt":
        decrypt(password, args.input, args.output)

if __name__ == "__main__":
    main()