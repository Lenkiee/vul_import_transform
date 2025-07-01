# utils.py
import os

def get_script_directory() -> str:
    """
    Returns the absolute path of the directory where the calling script is located.
    """
    return os.path.dirname(os.path.realpath(__file__))

def get_xlsx_files_in_directory(directory_path: str) -> list[str]:
    """
    Lists all .xlsx files in a given directory.

    Args:
        directory_path (str): The path to the directory to scan.

    Returns:
        list[str]: A list of filenames (not full paths) ending with '.xlsx'.
    """
    if not os.path.isdir(directory_path):
        return [] # Return empty list if directory doesn't exist

    return [f for f in os.listdir(directory_path) if f.endswith('.xlsx')]