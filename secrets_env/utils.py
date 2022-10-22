def removeprefix(s: str, prefix: str):
    # str.removeprefix is only available after python 3.9
    if s.startswith(prefix):
        return s[len(prefix) :]
    return s
