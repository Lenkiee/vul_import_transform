# gui_elements.py
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import pandas as pd
import warnings

# Import configurations and data processing function
from config import ENV_MAP, VPR_ORDER, REQUIRED_COLUMNS
from data_processing import create_final_format
from utils import get_script_directory, get_xlsx_files_in_directory # <--- THIS LINE IS CRUCIAL
                                                                  # Make sure 'get_script_directory'
                                                                  # and 'get_xlsx_files_in_directory'
                                                                  # are spelled exactly as they are in utils.py

# Suppress pandas UserWarnings for a cleaner console output
warnings.simplefilter("ignore", UserWarning)

class FinalExportGUI:
    def __init__(self, root: tk.Tk):
        """
        Initializes the main Tkinter window and sets up instance variables.

        Args:
            root (tk.Tk): The root Tkinter window instance, passed from main.py.
        """
        self.root = root
        self.root.title("JIRA Vulnerability Exporter")
        self.root.geometry("600x400") # Set initial window size

        self.file_path = None       # Stores the path to the selected Excel file
        self.env_selections = {}    # Dictionary to hold BooleanVar objects for environment checkboxes
        self.vpr_selections = {}    # Dictionary to hold BooleanVar objects for VPR checkboxes

        self._setup_ui() # Call method to build all GUI components

    def _setup_ui(self):
        """Sets up all the widgets and their layout within the GUI window."""
        # Main frame with padding for overall layout
        frame = ttk.Frame(self.root, padding=10)
        frame.pack(fill="both", expand=True)

        # --- File Selection Frame ---
        file_frame = ttk.LabelFrame(frame, text="Select Excel File", padding=10)
        file_frame.pack(fill="x", pady=5)

        self.file_var = tk.StringVar() # Variable to hold the selected file name for the dropdown
        # Combobox to display and select an Excel file from the current directory
        self.file_dropdown = ttk.Combobox(file_frame, textvariable=self.file_var, state="readonly", width=50)
        self.file_dropdown.pack(side="left", padx=5)

        self._populate_files_dropdown() # Populate the dropdown with .xlsx files from the script directory
        self.file_dropdown.bind('<<ComboboxSelected>>', self._on_file_selected) # Bind event for dropdown selection

        # --- Environment Selection Checkboxes Frame ---
        env_frame = ttk.LabelFrame(frame, text="Select Environments", padding=10)
        env_frame.pack(fill="x", pady=5)

        # Create a checkbox for each environment defined in ENV_MAP
        for env in ENV_MAP:
            var = tk.BooleanVar() # Tkinter variable to store checkbox state (True/False)
            ttk.Checkbutton(env_frame, text=env, variable=var).pack(side="left", padx=5)
            self.env_selections[env] = var # Store the BooleanVar for later retrieval

        # --- VPR Filter Checkboxes Frame ---
        vpr_frame = ttk.LabelFrame(frame, text="VPR Filter", padding=10)
        vpr_frame.pack(fill="x", pady=5)

        # Create a checkbox for each VPR level defined in VPR_ORDER
        for vpr in VPR_ORDER:
            var = tk.BooleanVar()
            ttk.Checkbutton(vpr_frame, text=vpr, variable=var).pack(side="left", padx=5)
            self.vpr_selections[vpr] = var

        # --- Export Button ---
        ttk.Button(frame, text="Export Final Format", command=self._export_data).pack(fill="x", pady=10)

        # --- Status Label ---
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(frame, textvariable=self.status_var).pack(fill="x", pady=5)

    def _populate_files_dropdown(self):
        """Populates the file selection dropdown with .xlsx files from the script's directory."""
        script_dir = get_script_directory() # Use utility function
        files = get_xlsx_files_in_directory(script_dir) # Use utility function
        self.file_dropdown['values'] = files

    def _on_file_selected(self, event):
        """Updates the internal file_path variable when a file is selected from the dropdown."""
        script_dir = get_script_directory() # Use utility function
        self.file_path = os.path.join(script_dir, self.file_var.get())

    def _export_data(self):
        """
        Handles the export process: reads data, applies filters, processes, and saves the output.
        This is the main action triggered by the "Export Final Format" button.
        """
        if not self.file_path:
            messagebox.showerror("Error", "Please select an Excel file first.")
            return

        try:
            # 1. Read the selected Excel file into a pandas DataFrame
            df = pd.read_excel(self.file_path)

            # 2. Validate required columns
            missing_cols = [col for col in REQUIRED_COLUMNS if col not in df.columns]
            if missing_cols:
                messagebox.showerror("Missing Columns", f"The selected Excel file is missing required columns: {', '.join(missing_cols)}")
                return

            # 3. Get user selections for environments and VPRs
            selected_envs = [env for env, var in self.env_selections.items() if var.get()]
            selected_vprs = [vpr for vpr, var in self.vpr_selections.items() if var.get()]

            if not selected_envs:
                messagebox.showwarning("Missing Selection", "Please select at least one environment to filter by.")
                return

            # Update status and force GUI refresh before potentially long processing
            self.status_var.set("Processing data...")
            self.root.update_idletasks()

            # 4. Call the core data processing function
            result_df = create_final_format(df, selected_envs, selected_vprs)

            if result_df is None:
                # The data_processing function handles the "No Data" warning, so just update status
                self.status_var.set("No relevant data found after filtering.")
                return

            # 5. Prompt user for save location
            save_path = filedialog.asksaveasfilename(
                defaultextension=".xlsx",
                filetypes=[("Excel files", "*.xlsx"), ("All files", "*.*")],
                title="Save Processed JIRA Data As"
            )
            if not save_path: # User cancelled the save dialog
                self.status_var.set("Export cancelled by user.")
                return

            # 6. Write the processed DataFrame to an Excel file with custom formatting
            self._write_excel_with_formatting(result_df, save_path)

            self.status_var.set("Exported successfully!")
            messagebox.showinfo("Success", f"Data successfully exported to:\n{save_path}")

        except pd.errors.EmptyDataError:
            messagebox.showerror("Error", "The selected Excel file is empty or contains no data.")
            self.status_var.set("Error: Empty Excel file.")
        except FileNotFoundError:
            messagebox.showerror("Error", "The selected file was not found. It might have been moved or deleted.")
            self.status_var.set("Error: File not found.")
        except Exception as e:
            # Catch any other unexpected errors during the process
            messagebox.showerror("Processing Error", f"An unexpected error occurred during export: {e}")
            self.status_var.set(f"Error: {e}")

    def _write_excel_with_formatting(self, df: pd.DataFrame, save_path: str):
        """
        Writes the DataFrame to an Excel file with specific formatting (headers, column widths).

        Args:
            df (pd.DataFrame): The DataFrame to write.
            save_path (str): The full path to save the Excel file.
        """
        with pd.ExcelWriter(save_path, engine="xlsxwriter") as writer:
            # Write DataFrame to a sheet named "Final Format", starting at row 1 (0-indexed)
            # so row 0 can be used for custom headers. Do not write pandas' default header.
            df.to_excel(writer, index=False, startrow=1, header=False, sheet_name="Final Format")

            workbook = writer.book # Get the XlsxWriter workbook object
            worksheet = writer.sheets["Final Format"] # Get the worksheet object

            # Define header format
            header_format = workbook.add_format({
                "bold": True,
                "bg_color": "#366092", # Dark blue background
                "font_color": "white",
                "border": 1,
                "text_wrap": True # Allow text to wrap within header cells
            })

            # Define a format for wrapping text in regular data cells
            wrap_format = workbook.add_format({"text_wrap": True})

            # Write custom headers and set column widths/formats
            for col_idx, col_name in enumerate(df.columns):
                # Write the header in the first row (row 0)
                worksheet.write(0, col_idx, col_name, header_format)

                # Determine column width: a minimum of header length, up to a max of 100
                # plus a small buffer (2). Handles empty columns gracefully.
                max_len_in_col = df[col_name].astype(str).map(len).max() if not df[col_name].empty else len(col_name)
                column_width = min(100, max(len(col_name), max_len_in_col) + 2)
                
                # Set the column width and apply the text wrapping format
                worksheet.set_column(col_idx, col_idx, column_width, wrap_format)

            # Freeze the first row so headers are always visible when scrolling
            worksheet.freeze_panes(1, 0)