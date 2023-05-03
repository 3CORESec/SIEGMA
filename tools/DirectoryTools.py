import os

class DirectoryTools:
    """
        Some common functions to manipulate Directories.
    """

    @staticmethod
    def get_file_extension(file_name: str) -> str:
        """
            Get the file extension.

        Args:
            file_name (str): File name.

        Returns:
            str: Return the type of the file.
        """

        extension = os.path.splitext(file_name)[1]
        return extension

    @staticmethod
    def get_files_by_extension(folder_path: str, get_sub_directories: bool = True, extension: str = ".yml") -> list[str]:
        """
            Get files by a determined extension.

        Args:
            folder_path (str): Directory to look for files.
            get_sub_directories (bool, optional): Pass True to collect all the file of the sub directories. Defaults to True.
            extension (str, optional): File extesion that you looking for . Defaults to ".yml".

        Returns:
            list[str]: Return all the files.
        """
    
        files: list[str] = []

        for folder_obj in DirectoryTools.get_files(folder_path):
            current_obj = os.path.join(folder_path, folder_obj)

            if os.path.isfile(current_obj) and DirectoryTools.get_file_extension(folder_obj) == extension:
                files.append(current_obj)

            elif get_sub_directories:
                DirectoryTools.get_folders_files(current_obj)

        return files

    @staticmethod
    def get_all_files_basename(folder_path: str) -> list[str]:
        """
            Get all files basename of the given folder.

        Args:
            folder_path (str): Folder path.

        Returns:
            list[str]:  All files basename of the given folder.
        """
     
        return os.listdir(folder_path)

    @staticmethod
    def it_is_a_directory(path: str) -> bool:
        """
            Check if the given path is a valid direcotry.

        Args:
            path (str): Directory path.

        Returns:
            bool: Returns True if the given path is a valid directory. 
        """

        if os.path.isdir(path):
            return True

        return False
