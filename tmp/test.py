from os import get_terminal_size

def progress_bar(progress, total_progress):
    percent = 100 * (float(progress) / float(total_progress))

    terminal_width = get_terminal_size()[0]
    bar_width = terminal_width - 10
    bar_progress = int(bar_width * (float(progress) / float(total_progress)))

    if bar_progress > bar_width or percent > 100:
        bar_progress = bar_width
        percent = 100

    bar_remaining = bar_width - bar_progress
    bar = '#' * bar_progress + '-' * bar_remaining
    print(f"\r[{bar}] {percent:.2f}%", end="\r")
    return progress + 16

if __name__ == "__main__":
    progress = 0
    for i in range(100):
        progress = progress_bar(progress, 100)
    print()
