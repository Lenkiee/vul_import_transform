# main.py
import tkinter as tk
# Import messagebox specifically for the error handling in this file
from tkinter import messagebox

# Add a print statement to confirm main.py is being executed
print("main.py started.") 

try:
    from gui_elements import FinalExportGUI
    print("FinalExportGUI imported successfully.")
except ImportError as e:
    print(f"Error importing FinalExportGUI: {e}")
    messagebox.showerror("Import Error", f"Failed to load application components: {e}") # Now messagebox is defined
    exit(1) # Exit if essential import fails

if __name__ == "__main__":
    print("Inside if __name__ == '__main__': block.")
    try:
        root = tk.Tk()
        print("Tkinter root window created.")
        app = FinalExportGUI(root)
        print("FinalExportGUI instance created.")
        root.mainloop()
        print("Tkinter main loop exited.") # This will only print after the window is closed
    except Exception as e:
        print(f"An error occurred during GUI execution: {e}")
        messagebox.showerror("Runtime Error", f"An unexpected error occurred: {e}") # Now messagebox is defined