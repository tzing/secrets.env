__all__ = ("Fore",)

try:
    import colorama

    colorama.init()

    from colorama import Fore

except ImportError:

    class _NoColor:
        def __getattr__(self, __name: str) -> str:
            setattr(self, __name, "")
            return ""

    Fore = _NoColor()
