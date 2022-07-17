from matplotlib import pyplot as plt
import numpy as np

# Set the figure size
plt.rcParams["figure.figsize"] = [5.00, 5.00]
plt.rcParams["figure.autolayout"] = True


# Random data points
with open("/Users/gabriellindeblad/Documents/GitHub/AES-Python/tmp/test_files/data.txt", "rb") as f:
    data = f.read()
    data = [i for i in data]
    data = [data[x:x+32] for x in range(0, len(data), 32)]
    #data = data[:-1]
print(data)


# Plot the data using imshow with gray colormap
plt.imshow(data, interpolation=None, cmap="gray")

# Display the plot
plt.show()