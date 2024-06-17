from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import os
import time
import matplotlib.pyplot as plt

def split_message(message, chunk_size):
    return [message[i:i+chunk_size] for i in range(0, len(message), chunk_size)]

def encrypt_message(public_key, message, chunk_size):
    encrypted_chunks = []
    for chunk in split_message(message, chunk_size):
        encrypted_chunks.append(public_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ))
    return encrypted_chunks

def decrypt_message(private_key, encrypted_chunks):
    decrypted_chunks = []
    for chunk in encrypted_chunks:
        decrypted_chunks.append(private_key.decrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ))
    return b"".join(decrypted_chunks)

# Key sizes to test
key_sizes = [2048, 3072, 4096, 8192]

# Number of iterations
num_iterations = 10

# Lists for storing average times
avg_key_gen_times = []
avg_encrypt_times = []
avg_decrypt_times = []

for key_size in key_sizes:
    key_gen_times = []
    encrypt_times = []
    decrypt_times = []

    chunk_size = (key_size // 8) - 2*32 - 2  # Calculate chunk size for RSA encryption with OAEP and SHA-256

    for _ in range(num_iterations):
        before_gen = time.perf_counter()
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        public_key = private_key.public_key()
        after_gen = time.perf_counter()
        key_gen_times.append(after_gen - before_gen)

        long_plaintext = os.urandom(2048)

        before_encrypt = time.perf_counter()
        long_ciphertext = encrypt_message(public_key, long_plaintext, chunk_size)
        after_encrypt = time.perf_counter()
        encrypt_times.append(after_encrypt - before_encrypt)

        before_decrypt = time.perf_counter()
        long_plaintext_2 = decrypt_message(private_key, long_ciphertext)
        after_decrypt = time.perf_counter()
        decrypt_times.append(after_decrypt - before_decrypt)

        # Verify the decryption is correct
        assert long_plaintext == long_plaintext_2, "Decrypted plaintext does not match original"

    # Calculate average times for each key size
    avg_key_gen_time = sum(key_gen_times) / num_iterations
    avg_encrypt_time = sum(encrypt_times) / num_iterations
    avg_decrypt_time = sum(decrypt_times) / num_iterations

    # Print information for each key size
    print(f"Key Generation Time ({key_size} bits): {avg_key_gen_time:0.4f} seconds")
    print(f"Avg Encrypt Time ({key_size} bits): {avg_encrypt_time:0.4f} seconds")
    print(f"Avg Decrypt Time ({key_size} bits): {avg_decrypt_time:0.4f} seconds")
    print()  # Separate key sizes in the command line

    # Store average times for plotting
    avg_key_gen_times.append(avg_key_gen_time)
    avg_encrypt_times.append(avg_encrypt_time)
    avg_decrypt_times.append(avg_decrypt_time)

# Plotting the times using line graph
plt.plot(key_sizes, avg_encrypt_times, marker='o', label='RSA Encrypt')
plt.plot(key_sizes, avg_decrypt_times, marker='s', label='RSA Decrypt')
plt.plot(key_sizes, avg_key_gen_times, marker='x', label='Key Generation Time')

plt.xlabel('Security (bits)')
plt.ylabel('Average Time (seconds)')
plt.title('RSA Encryption and Decryption with Chunking')
plt.legend()
plt.show()
