from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import os
import time
import matplotlib.pyplot as plt

def encrypt_decrypt_times(public_key, private_key, short_plaintext, iterations=100):
    times_encrypt = []
    times_decrypt = []

    for _ in range(iterations):
        before_encrypt = time.perf_counter()
        try:
            short_ciphertext = public_key.encrypt(
                short_plaintext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            print(f"Encryption failed: {e}")
            continue
        after_encrypt = time.perf_counter()
        times_encrypt.append(after_encrypt - before_encrypt)

        before_decrypt = time.perf_counter()
        try:
            short_plaintext_2 = private_key.decrypt(
                short_ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            print(f"Decryption failed: {e}")
            continue
        after_decrypt = time.perf_counter()
        times_decrypt.append(after_decrypt - before_decrypt)

    return times_encrypt, times_decrypt

# Key sizes to test
key_sizes = [2048, 3072, 4096, 8192]  # Add more key sizes as needed

# Lists for storing average times
avg_encrypt_times = []
avg_decrypt_times = []
key_gen_times = []

for key_size in key_sizes:
    before_gen = time.perf_counter()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    after_gen = time.perf_counter()
    key_gen_times.append(after_gen - before_gen)

    # We can print out the private-key.
    private_key_str = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    print(private_key_str.decode("utf-8"))

    public_key = private_key.public_key()

    # We can print out the public-key.
    public_key_str = public_key.public_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PublicFormat.PKCS1
    )
    print(public_key_str.decode("utf-8"))

    num_of_iterations = 100

    # Change 128 to 4096
    # short_plaintext = os.urandom(4096)
    short_plaintext = b'This is a test message for encryption.'

    # Obtain the times for encryption and decryption
    times_encrypt, times_decrypt = encrypt_decrypt_times(public_key, private_key, short_plaintext)

    # Calculate and store the average times
    avg_encrypt_time = sum(times_encrypt) / num_of_iterations
    avg_decrypt_time = sum(times_decrypt) / num_of_iterations
    avg_encrypt_times.append(avg_encrypt_time)
    avg_decrypt_times.append(avg_decrypt_time)

    # Print key generation time and average times for each key size
    print(f"\nKey Generation Time ({key_size} bits): {after_gen - before_gen:0.4f} seconds")
    print(f"Average Encrypt Time ({key_size} bits): {avg_encrypt_time:0.4f} seconds")
    print(f"Average Decrypt Time ({key_size} bits): {avg_decrypt_time:0.4f} seconds")

# Plotting the times
plt.plot(key_sizes, avg_encrypt_times, 'o-r', label='Encrypt Time')
plt.plot(key_sizes, avg_decrypt_times, 's-g', label='Decrypt Time')
plt.plot(key_sizes, key_gen_times, 'x-b', label='Key Generation Time')
plt.xlabel('Security (bits)')
plt.ylabel('Average Time (seconds)')
plt.title('Timing RSA Encryption and Decryption Operations')
plt.legend()
plt.show()
