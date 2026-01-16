from distutils.core import setup, Extension

def main():
    setup(
        name="money",
        ext_modules=[Extension("money", ["chall.c"])]
    )

if __name__ == "__main__":
    main()
