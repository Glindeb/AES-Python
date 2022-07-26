

def progress_bar(progress, total_progress):
    percent = 100 * (float(progress) / float(total_progress))
    if percent > 100:
        percent = 100
    bar = '#' * int(percent) + '-' * (100 - int(percent))
    print(f"\r[{bar}] {percent:.2f}%", end="\r")
    return progress + 16

if __name__ == "__main__":
    progress = 0
    for i in range(100):
        progress = progress_bar(progress, 100)
    print()