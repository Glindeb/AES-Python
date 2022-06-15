from matplotlib import pyplot as plt

# Set the figure size
plt.rcParams["figure.figsize"] = [5.00, 5.00]
plt.rcParams["figure.autolayout"] = True


# Random data points
#with open("/Users/gabriellindeblad/Documents/GitHub/AES-Python/tmp/test_files/data.txt.enc", "rb") as f:
#    data = f.read().splitlines()
#    print(data)
#    for index, pice in enumerate(data):
#        data[index] = [i for i in pice]

with open("/Users/gabriellindeblad/Documents/GitHub/AES-Python/tmp/test_files/data.txt.enc", "rb") as f:
    data = f.read()
    data = [i for i in data]
    data = [data[x:x+192] for x in range(0, len(data), 192)]
    #data = data[:-1]
print(data)

print(data)


plt.title('adjust axis scale')

# Plot the data using imshow with gray colormap & aspect set to auto
plt.imshow(data, interpolation=None, cmap="gray", aspect="auto")

# Display the plot
plt.show()