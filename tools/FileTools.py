import os
import json


class FileTools:
    """
                Provides common functions to work with files.
    """

    @staticmethod
    def get_file_basename(path: str) -> str:
        """
            Get the basename of a file.

        Args:
            path (str): Pass the path of the file.

        Returns:
            str: Filename of the path given as argument.
        """

        return os.path.basename(path)

    @staticmethod
    def file_path(dir_path: str, file_path: str) -> str:
        """
            Join the directory path with the file path.

        Args:
            dir_path (str): Directory path.
            file_path (str): File path.

        Returns:
            str: File path.
        """

        return os.path.join(dir_path, file_path)

    @staticmethod
    def get_dirname(path: str) -> str:
        """
            Return the directory of a file. Pass the full file path as an argument.

        Args:
            path (str): File path.

        Returns:
            str: Directory path.
        """

        return os.path.dirname(path)

    @staticmethod
    def load_json_file(file_path: str) -> dict[str, any]:
        """
            Loads a given JSON file..

        Args:
            file_path (str): File path to be loaded.

        Returns:
            dict[str, any]: File content.
        """

        with open(file_path, "r") as json_file:
            config_dict = json.load(json_file)

        return config_dict

    @staticmethod
    def get_file_extension_name(file_path: str) -> str:
        """
            Returns the extension of a given file.

        Args:
            file_path (str): File path.

        Returns:
            str: Extension name.
        """

        return os.path.splitext(file_path)[1]

    @staticmethod
    def check_if_is_a_file(path: str) -> bool:
        """
            Check if a file exists by validating its full path.

        Args:
            path (str): Full path.

        Returns:
            bool: Return True if it is a valid path.
        """

        absolute_path = os.path.abspath(path)
        return os.path.isfile(absolute_path)
