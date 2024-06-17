from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
import os
import time
import matplotlib.pyplot as plt

# Number of iterations
num_iterations = 100

def dsa_operations_times(key_size):
    # Measure DSA key generation time once
    before_generate = time.perf_counter()
    private_key = dsa.generate_private_key(key_size=key_size)
    after_generate = time.perf_counter()
    generate_time = after_generate - before_generate

    public_key = private_key.public_key()
    message = os.urandom(1024)
    times_sign = []
    times_verify = []

    for _ in range(num_iterations):
        before_sign = time.perf_counter()
        signature = private_key.sign(message, hashes.SHA256())
        after_sign = time.perf_counter()
        times_sign.append(after_sign - before_sign)

        before_verify = time.perf_counter()
        public_key.verify(signature, message, hashes.SHA256())
        after_verify = time.perf_counter()
        times_verify.append(after_verify - before_verify)

    # Calculate and print the average times for each key size
    average_sign_time = sum(times_sign) / num_iterations
    average_verify_time = sum(times_verify) / num_iterations

    print(f"\nKey Size: {key_size} bits")
    print(f"Key Generation Time: {generate_time:0.4f} seconds")
    print(f"Average Sign Time: {average_sign_time:0.4f} seconds")
    print(f"Average Verify Time: {average_verify_time:0.4f} seconds")

    return generate_time, average_sign_time, average_verify_time

# DSA Key Sizes
dsa_key_sizes = [1024, 2048, 3072, 4096]

generate_times_all = []
times_sign_all = []
times_verify_all = []

# Lists to store key sizes and average times for plotting on x-axis
key_sizes_all = []
avg_sign_times_all = []
avg_verify_times_all = []

for key_size in dsa_key_sizes:
    key_sizes_all.append(key_size)
    generate_time, avg_sign_time, avg_verify_time = dsa_operations_times(key_size)
    
    # Extend the lists with times
    generate_times_all.append(generate_time)
    avg_sign_times_all.append(avg_sign_time)
    avg_verify_times_all.append(avg_verify_time)

# Plotting the times
plt.figure(figsize=(12, 6))

# Plotting average sign and verify times
plt.plot(key_sizes_all, avg_sign_times_all, 'o-r', label='Average Sign Time')
plt.plot(key_sizes_all, avg_verify_times_all, 's-g', label='Average Verify Time')
plt.plot(key_sizes_all, generate_times_all, 'x-b', label='Key Generation Time')

# Set labels and titles
plt.xlabel('Security (bits)')
plt.ylabel('Time (seconds)')
plt.title(f'Timing DSA Operations ({num_iterations} iterations)')
plt.legend()

# Show the plot
plt.show()
