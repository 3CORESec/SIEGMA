from importlib import import_module
from pathlib import Path
from pkgutil import iter_modules
from inspect import getmembers, isclass


# Use this to collect all Converters
all_converters = {
    submodule.lower(): cls          # Name Of Converor: ConverorClass
    for _, submodule, _ in iter_modules([ str(Path(__file__).resolve().parent) ])       # Iterate over modules, str around Path is due to issue with PosixPath from Python 3.10
    for name, cls in getmembers(import_module(__name__ + "." + submodule, isclass))     # Iterate over classes
    if name.endswith("Converter")     # Class filtering (Collect only converters)
}
