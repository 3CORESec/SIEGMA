from sigma.backends.elasticsearch import LuceneBackend
from enum import Enum

class Backends(Enum):
    """
        Enun with all available backends
    """
    elastic = LuceneBackend

    @classmethod
    def get_backend(cls, backend_name: str) -> callable:
        """
            Use this method to get a backend function

        Args:
            backend_name (str): Pass the name of the backend

        Returns:
            callable: It returns a backend function
        """

        return cls[backend_name]
