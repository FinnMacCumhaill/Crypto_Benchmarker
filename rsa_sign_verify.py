from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import os
import time
import matplotlib.pyplot as plt

def sign_verify_times(private_key, public_key, message, iterations=100):
    times_sign = []
    times_verify = []

    for _ in range(iterations):
        before_sign = time.perf_counter()
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        after_sign = time.perf_counter()
        times_sign.append(after_sign - before_sign)

        before_verify = time.perf_counter()
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        after_verify = time.perf_counter()
        times_verify.append(after_verify - before_verify)

    return times_sign, times_verify

# RSA Key Sizes
rsa_key_sizes = [2048, 3072, 4096, 8192]

# Lists to store times
times_key_gen = []
times_sign_all = []
times_verify_all = []

for key_size in rsa_key_sizes:
    before_gen = time.perf_counter()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    after_gen = time.perf_counter()
    times_key_gen.append(after_gen - before_gen)
    print(f"\nKey Generation Time ({key_size} bits): {after_gen - before_gen:0.4f} seconds")

    message = os.urandom(2048)

    num_of_iterations = 100

    # Obtain the times for signing and verification
    times_sign, times_verify = sign_verify_times(private_key, public_key, message)  # Removed 'iterations'

    # Calculate and print the average times
    average_sign_time = sum(times_sign) / num_of_iterations  # Corrected variable names
    average_verify_time = sum(times_verify) / num_of_iterations # Corrected variable names
    print(f"Average Sign Time: {average_sign_time:0.4f} seconds")
    print(f"Average Verify Time: {average_verify_time:0.4f} seconds")

    # Extend the lists with times
    times_sign_all.append(average_sign_time)
    times_verify_all.append(average_verify_time)

# Plotting the times
plt.plot(rsa_key_sizes, times_sign_all, 'o-r', label='RSA Sign Time')
plt.plot(rsa_key_sizes, times_verify_all, 's-g', label='RSA Verify Time')
plt.plot(rsa_key_sizes, times_key_gen, 'x-b', label= 'Key Generation Time')
plt.xlabel('Security (bits)')
plt.ylabel('Time (seconds)')
plt.title(f'Timing RSA Sign and Verify Operations')
plt.legend()
plt.show()
