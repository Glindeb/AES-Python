from PyAES.encrypt import encrypt
from PyAES.decrypt import decrypt
from Analyze_init import setup, clean
from timeit import timeit
from datetime import timedelta


def main():
    # Initialize and create test data
    setup()

    # Preform analysis tests
    timeit.d

    # Display time
    print(timedelta(seconds=start - end))

    # Cleaning up after test
    clean()


if __name__ == '__main__':
    main()