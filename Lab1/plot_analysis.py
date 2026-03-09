import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Read the data
try:
    data = pd.read_csv('bruteforce_data.csv')
except FileNotFoundError:
    print("Error: bruteforce_data.csv not found!")
    print("Please run bruteforce.exe first to generate the data.")
    exit(1)

# Extract data
lengths = data['Message_Length'].values
times = data['Time_Microseconds'].values

# Create figure with subplots
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

# Plot 1: Time vs Message Length
ax1.plot(lengths, times, 'b-o', linewidth=2, markersize=6, label='Actual Time')

# Linear fit
coeffs = np.polyfit(lengths, times, 1)
fit_line = np.poly1d(coeffs)
ax1.plot(lengths, fit_line(lengths), 'r--', linewidth=2, label=f'Linear Fit: y={coeffs[0]:.4f}x + {coeffs[1]:.2f}')

ax1.set_xlabel('Message Length (characters)', fontsize=12, fontweight='bold')
ax1.set_ylabel('Time to Try All 26 Keys (μs)', fontsize=12, fontweight='bold')
ax1.set_title('Brute-Force Attack Time vs Message Length\nCaesar Cipher (26 possible keys)', 
              fontsize=13, fontweight='bold')
ax1.grid(True, alpha=0.3)
ax1.legend(fontsize=10)

# Plot 2: Time Complexity Visualization
ax2.bar(range(len(lengths)), times, color='steelblue', alpha=0.7, edgecolor='black')
ax2.set_xlabel('Test Number', fontsize=12, fontweight='bold')
ax2.set_ylabel('Time (μs)', fontsize=12, fontweight='bold')
ax2.set_title('Time Distribution Across Different Message Lengths', 
              fontsize=13, fontweight='bold')
ax2.grid(True, alpha=0.3, axis='y')

# Add annotations
for i, (l, t) in enumerate(zip(lengths, times)):
    if i % 4 == 0:  # Annotate every 4th bar to avoid clutter
        ax2.text(i, t, f'{l}', ha='center', va='bottom', fontsize=8)

plt.tight_layout()

# Save figure
plt.savefig('bruteforce_analysis.png', dpi=300, bbox_inches='tight')
print("Graph saved as: bruteforce_analysis.png")

# Display statistics
print("\n=== Statistical Analysis ===")
print(f"Total tests: {len(lengths)}")
print(f"Message length range: {min(lengths)} - {max(lengths)} characters")
print(f"Time range: {min(times):.2f} - {max(times):.2f} μs")
print(f"Average time: {np.mean(times):.2f} μs")
print(f"Linear relationship coefficient: {coeffs[0]:.6f} μs/char")
print(f"\nTime Complexity: T(n) = 26 * O(n)")
print(f"Each character requires ~{coeffs[0]:.6f} μs to process across all 26 keys")

plt.show()