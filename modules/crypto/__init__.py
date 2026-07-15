if __name__ == "__main__":
    print("Поехали!!")
else:
    from .analyzer import analyze_crypto
    from .detector import detect_cipher, detect_encoding

    __all__ = ["analyze_crypto", "detect_cipher", "detect_encoding"]

