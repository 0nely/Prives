from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("prives")
except PackageNotFoundError:
    __version__ = "unknown"