from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import os
import time
import matplotlib.pyplot as plt

# Number of iterations
num_iterations = 100


# List of supported EC curves and their corresponding security bits
supported_curves = [
    (ec.SECP192R1(), 192),
    (ec.SECP256R1(), 256),
    (ec.SECP384R1(), 384),
    (ec.SECP521R1(), 521),
]

# Lists to store average times for each key size
avg_sign_times = []
avg_verify_times = []
key_gen_times = []

for curve, security_bits in supported_curves:
    times_sign = []
    times_verify = []

    key_size = curve.key_size

    before_gen = time.perf_counter()
    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()
    after_gen = time.perf_counter()
    key_gen_times.append(after_gen - before_gen)

    message = os.urandom(24)

    for _ in range(num_iterations):
        before_sign = time.perf_counter()
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        after_sign = time.perf_counter()
        times_sign.append(after_sign - before_sign)

        before_verify = time.perf_counter()
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        after_verify = time.perf_counter()
        times_verify.append(after_verify - before_verify)

    # Calculate and store the average times
    avg_sign_time = sum(times_sign) / num_iterations
    avg_verify_time = sum(times_verify) / num_iterations
    avg_sign_times.append(avg_sign_time)
    avg_verify_times.append(avg_verify_time)

    # Print key generation time and average times for each key size
    print(f"\nKey Generation Time ({key_size} bits): {after_gen - before_gen:0.4f} seconds")
    print(f"Average Sign Time ({key_size} bits): {avg_sign_time:0.4f} seconds")
    print(f"Average Verify Time ({key_size} bits): {avg_verify_time:0.4f} seconds")

# Plotting the times
key_sizes = [curve.key_size for curve, _ in supported_curves]

plt.plot(key_sizes, avg_sign_times, 'o-r', label='ECC Sign')
plt.plot(key_sizes, avg_verify_times, 's-g', label='ECC Verify')
plt.plot(key_sizes, key_gen_times, 'x-b', label='Key Generation Time')

# Display the plot
plt.xlabel('Security (bits)')
plt.ylabel('Average Time (seconds)')
plt.title(f'Timing ECC Sign and Verify Operations ({num_iterations} iterations)')
plt.legend()
plt.show()
