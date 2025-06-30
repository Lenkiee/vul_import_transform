import os
import pandas as pd
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import warnings
import re

# Suppress pandas UserWarnings that might pop up during operations, keeping the console cleaner.
warnings.simplefilter("ignore", UserWarning)

# --- Configuration Section ---
# These dictionaries and lists define the core logic and mappings of your data.

# ENV_MAP: Maps shorter environment codes from your input data to a standardized, sortable format.
# This ensures that environments like "PRD" (Production) are correctly sorted as "1. Production".
ENV_MAP = {
    "Dev": "4. Development",
    "TST": "3. Test",
    "ACP": "2. Acceptance",
    "PRD": "1. Production"
}

# HOSTNAME_APPLICATION_MAP: This is the SOLE source for mapping hostnames to specific applications.
# It's crucial for determining the 'Application' part of your JIRA ticket titles.
# You MUST populate this dictionary with all relevant hostnames and their corresponding application names.
HOSTNAME_APPLICATION_MAP = {
    "SVNIBCOSXD103": "OneSumX",
    "SVNIBCOSXD105": "OneSumX",
    "SVNIBCOSXT103": "OneSumX",
    "SVNIBCOSXA103": "OneSumX",
    "SVNIBCOSXA105": "OneSumX",
    "SVNIBCOSXP103": "OneSumX",
    "SVNIBCSQLD027": "OneSumX",
    "SVNIBCSQLD127": "OneSumX",
    "SVNIBCSQLT027": "OneSumX",
    "SVNIBCSQLA027": "OneSumX",
    "SVNIBCSQLA127": "OneSumX",
    "SVNIBCSQLP027": "OneSumX",
    "SVNIBCSQLD031": "FinDM",
    "SVNIBCSQLT031": "FinDM",
    "SVNIBCSQLA031": "FinDM",
    "SVNIBCSQLP031": "FinDM",
    "SVNIBCOSXD104": "RegPro",
    "SVNIBCOSXT104": "RegPro",
    "SVNIBCOSXA104": "RegPro",
    "SVNIBCOSXA106": "RegPro",
    "SVNIBCOSXP104": "RegPro",
    "SVNIBCSQLD028": "RegPro",
    "SVNIBCSQLT028": "RegPro",
    "SVNIBCSQLA028": "RegPro",
    "SVNIBCSQLA128": "RegPro",
    "SVNIBCSQLP028": "RegPro",
    "SVNIBCSQLD033": "Anacredit",
    "SVNIBCSQLT033": "Anacredit",
    "SVNIBCSQLA033": "Anacredit",
    "SVNIBCSQLP033": "Anacredit",
    # Add more hostname-to-application mappings here as needed.
}

# GROUP_KEY: Defines the primary column used to group vulnerabilities into individual JIRA tickets.
# All rows sharing the same value in this column will be consolidated into one ticket.
GROUP_KEY = "Synopsis"

# REQUIRED_COLUMNS: A list of column names that MUST be present in your input Excel file.
# The script will check for these and show an error if any are missing.
REQUIRED_COLUMNS = [
    'Hostname',                 # Identifies the affected machine.
    'Vulnerability',            # The name of the vulnerability.
    'Remediation (Solution)',   # How to fix the vulnerability.
    'Role',                     # The role of the host (e.g., "Application Server").
    'Environment',              # The environment of the host (e.g., "PRD", "Dev").
    'Synopsis',                 # A brief summary, used for grouping tickets.
    'Plugin Text',              # Detailed output from the vulnerability scanner.
    'VPR',                      # Vulnerability Priority Rating (Critical, High, Medium, Low, Undefined).
    'VPR Score',                # Numerical score for VPR.
    'First Discovered',         # Date when the vulnerability was first found.
    'CVE'                       # Common Vulnerabilities and Exposures ID.
    # --- HOW TO ADD MORE REQUIRED COLUMNS ---
    # If your input Excel MUST contain a new column for the script to run,
    # add its exact name to this list. For example:
    # 'NewMandatoryColumnName',
]

# VPR_ORDER: Defines the custom sorting order for VPRs.
# This ensures that "Critical" comes before "High", etc., in the output.
VPR_ORDER = {
    "Undefined": 0, "Critical": 1, "High": 2, "Medium": 3, "Low": 4
}

# --- Core Logic Function ---
def create_final_format(df, selected_envs, selected_vprs):
    """
    Processes the input DataFrame to create the final JIRA-formatted data.

    Args:
        df (pd.DataFrame): The input DataFrame loaded from the Excel file.
        selected_envs (list): A list of environments selected by the user (e.g., ['Dev', 'PRD']).
        selected_vprs (list): A list of VPRs selected by the user (e.g., ['Critical', 'High']).

    Returns:
        pd.DataFrame: A DataFrame with 'Ticket_Title' and 'JIRA_Description' columns,
                      or None if no data is found after filtering.
    """
    # Filter the DataFrame based on user-selected environments.
    allowed_envs = [ENV_MAP[env] for env in selected_envs]
    df = df[df['Environment'].isin(allowed_envs)]

    # Filter the DataFrame based on user-selected VPRs.
    if selected_vprs: # Only apply filter if VPRs were selected
        df = df[df['VPR'].isin(selected_vprs)]

    # Check if the DataFrame is empty after filtering.
    if df.empty:
        messagebox.showwarning("No Data", "No rows found after applying filters.")
        return None

    # Add a 'vpr_rank' column to enable custom sorting based on VPR_ORDER.
    # 'fillna(99)' handles any VPR values not found in VPR_ORDER, placing them at the end.
    df['vpr_rank'] = df['VPR'].map(VPR_ORDER).fillna(99)
    # Sort the DataFrame first by the GROUP_KEY (Synopsis), then by the custom VPR rank.
    df = df.sort_values(by=[GROUP_KEY, 'vpr_rank'])

    # Initialize an empty list to store dictionaries, which will later become the output DataFrame rows.
    rows = []

    # Group the filtered and sorted DataFrame by GROUP_KEY (Synopsis) and VPR.
    # Each 'group' represents a set of related vulnerabilities that will form one JIRA ticket.
    for (synopsis, vpr), group in df.groupby([GROUP_KEY, 'VPR']):
        highest_vpr = vpr # The VPR for this specific group (synopsis and VPR level)

        # Initialize a set to store unique application names found within this group.
        # Using a set automatically handles duplicates.
        group_applications = set()
        
        # Iterate through each individual row within the current 'group'.
        # Each 'row' corresponds to a single affected host for this vulnerability synopsis.
        for _, row in group.iterrows():
            hostname = row['Hostname']

            # --- APPLICATION DETERMINATION LOGIC ---
            # This is the single point where the application is determined based on the hostname.
            if hostname in HOSTNAME_APPLICATION_MAP:
                group_applications.add(HOSTNAME_APPLICATION_MAP[hostname])
            else:
                # If a hostname is not found in the map, mark it as "N/A".
                group_applications.add("N/A")

        # Process the collected application names for the ticket title.
        mapped_apps_list = sorted(list(group_applications))
        # If "N/A" is present alongside other valid applications, remove "N/A" for a cleaner title.
        if "N/A" in mapped_apps_list and len(mapped_apps_list) > 1:
            mapped_apps_list.remove("N/A")
        
        # Join the unique application names into a comma-separated string for the title.
        # If no applications were mapped (e.g., only "N/A" was present and removed, or the set was empty), default to "N/A".
        app_string = ", ".join(mapped_apps_list) if mapped_apps_list else "N/A"

        # Construct the JIRA Ticket Title.
        ticket_title = f"{app_string} - {highest_vpr} - {group.iloc[0]['Vulnerability']}"

        # Initialize the JIRA Description string.
        description = "Affected Hosts:\n"
        
        # Iterate through each row (affected host) in the current group again
        # to build a detailed description for each specific host.
        for _, row in group.iterrows():
            # Retrieve 'Plugin Text', cleaning any HTML-like tags, and defaulting to 'N/A'.
            plugin_text = re.sub(r"</?plugin_output>", "", row.get('Plugin Text', 'N/A'), flags=re.IGNORECASE).strip()
            # Retrieve 'First Discovered' date, defaulting to 'N/A'.
            first_discovered = row.get('First Discovered', 'N/A')
            # Retrieve 'CVE' ID, defaulting to 'N/A'.
            cve = row.get('CVE', 'N/A')

            # --- HOW TO ADD MORE COLUMNS TO THE JIRA DESCRIPTION ---
            # To add more columns from your Excel file into the JIRA_Description:
            # 1. Get the exact column name from your Excel file (e.g., 'NewDataColumn').
            # 2. Use row.get('Column Name', 'N/A') to safely retrieve its value.
            #    This prevents errors if the column is missing or the cell is empty.
            # 3. Add a new f-string line within the 'description +=' block below.

            # Example: Let's say you have 'CVSS_Score' and 'Responsible_Team' columns:
            # cvss_score = row.get('CVSS_Score', 'N/A')
            # responsible_team = row.get('Responsible_Team', 'N/A')

            description += (
                f"* Host: {row['Hostname']}\n"
                f"  Environment: {row['Environment']}\n"
                f"  Role: {row['Role']}\n" # Role is still included in description for context
                f"  Remediation: {row['Remediation (Solution)']}\n"
                f"  First Discovered: {first_discovered}\n"
                f"  CVE: {cve}\n"
                f"  Plugin Text:\n{plugin_text}\n\n"
                # --- INSERT NEW COLUMNS INTO THE DESCRIPTION STRING HERE ---
                # Example of adding the new columns from above:
                # f"  CVSS Score: {cvss_score}\n"
                # f"  Responsible Team: {responsible_team}\n\n" # Add an extra newline if needed for formatting
            )
            # Make sure to maintain proper indentation (4 spaces) for clarity.


        # Append the generated ticket title and description as a dictionary to the 'rows' list.
        rows.append({"Ticket_Title": ticket_title, "JIRA_Description": description})

    # Convert the list of dictionaries into a pandas DataFrame.
    return pd.DataFrame(rows)


# --- GUI Class Definition ---
# This class handles the creation and functionality of the Tkinter graphical user interface.
class FinalExportGUI:
    def __init__(self):
        """Initializes the main Tkinter window and sets up instance variables."""
        self.root = tk.Tk() # Create the main window.
        self.root.title("JIRA Vulnerability Exporter") # Set the window title.
        self.root.geometry("600x400") # Set the initial window size.

        self.file_path = None # Stores the path to the selected Excel file.
        self.env_selections = {} # Dictionary to hold BooleanVar objects for environment checkboxes.
        self.vpr_selections = {} # Dictionary to hold BooleanVar objects for VPR checkboxes.

        self._setup_ui() # Call method to build the GUI components.

    def _setup_ui(self):
        """Sets up all the widgets and layouts in the GUI window."""
        # Main frame for padding
        frame = ttk.Frame(self.root, padding=10)
        frame.pack(fill="both", expand=True)

        # Frame for file selection
        file_frame = ttk.LabelFrame(frame, text="Select Excel File", padding=10)
        file_frame.pack(fill="x", pady=5)

        self.file_var = tk.StringVar() # Variable to hold the selected file name for the dropdown.
        # Dropdown (Combobox) to select an Excel file from the current directory.
        self.file_dropdown = ttk.Combobox(file_frame, textvariable=self.file_var, state="readonly", width=50)
        self.file_dropdown.pack(side="left", padx=5)

        self._populate_files() # Populate the dropdown with .xlsx files.

        # Bind an event to update file_path when a selection is made in the dropdown.
        self.file_dropdown.bind('<<ComboboxSelected>>', self._file_selected)

        # Frame for environment selection checkboxes.
        env_frame = ttk.LabelFrame(frame, text="Select Environments", padding=10)
        env_frame.pack(fill="x", pady=5)

        # Create a checkbox for each environment defined in ENV_MAP.
        for env in ENV_MAP:
            var = tk.BooleanVar() # Tkinter variable to store checkbox state (True/False).
            ttk.Checkbutton(env_frame, text=env, variable=var).pack(side="left", padx=5)
            self.env_selections[env] = var # Store the BooleanVar for later retrieval.

        # Frame for VPR filter checkboxes.
        vpr_frame = ttk.LabelFrame(frame, text="VPR Filter", padding=10)
        vpr_frame.pack(fill="x", pady=5)

        # Create a checkbox for each VPR level defined in VPR_ORDER.
        for vpr in VPR_ORDER:
            var = tk.BooleanVar()
            ttk.Checkbutton(vpr_frame, text=vpr, variable=var).pack(side="left", padx=5)
            self.vpr_selections[vpr] = var

        # Button to trigger the export process.
        ttk.Button(frame, text="Export Final Format", command=self._export).pack(fill="x", pady=10)

        # Label to display status messages to the user.
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(frame, textvariable=self.status_var).pack(fill="x", pady=5)

    def _populate_files(self):
        """Populates the file selection dropdown with .xlsx files in the script's directory."""
        # Get the directory where the script is located.
        folder = os.path.dirname(os.path.realpath(__file__))
        # List all .xlsx files in that directory.
        files = [f for f in os.listdir(folder) if f.endswith('.xlsx')]
        self.file_dropdown['values'] = files # Update the dropdown options.

    def _file_selected(self, event):
        """Updates the internal file_path variable when a file is selected from the dropdown."""
        folder = os.path.dirname(os.path.realpath(__file__))
        self.file_path = os.path.join(folder, self.file_var.get())

    def _export(self):
        """
        Handles the export process: reads data, applies filters, processes, and saves the output.
        """
        if not self.file_path:
            messagebox.showerror("Error", "Please select an Excel file.")
            return

        try:
            # Read the selected Excel file into a pandas DataFrame.
            df = pd.read_excel(self.file_path)

            # Check if all REQUIRED_COLUMNS are present in the loaded DataFrame.
            missing_cols = [col for col in REQUIRED_COLUMNS if col not in df.columns]
            if missing_cols:
                messagebox.showerror("Missing Columns", f"Missing required columns: {', '.join(missing_cols)}")
                return

            # Get the list of selected environments from the checkboxes.
            selected_envs = [env for env, var in self.env_selections.items() if var.get()]
            # Get the list of selected VPRs from the checkboxes.
            selected_vprs = [vpr for vpr, var in self.vpr_selections.items() if var.get()]

            if not selected_envs:
                messagebox.showwarning("Missing Selection", "Select at least one environment.")
                return

            self.status_var.set("Processing...") # Update status bar
            self.root.update() # Force GUI update to show "Processing..."

            # Call the core logic function to create the final formatted data.
            result = create_final_format(df, selected_envs, selected_vprs)

            if result is None:
                self.status_var.set("No data after filtering.")
                return

            # Open a file dialog to let the user choose where to save the output Excel file.
            save_path = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx")])
            if not save_path: # If user cancels save dialog
                self.status_var.set("Export cancelled.")
                return

            # Write the result DataFrame to an Excel file using xlsxwriter engine for custom formatting.
            with pd.ExcelWriter(save_path, engine="xlsxwriter") as writer:
                # Write DataFrame to a sheet named "Final Format", starting at row 1 (0-indexed)
                # so row 0 can be used for headers. Do not write pandas default header.
                result.to_excel(writer, index=False, startrow=1, header=False, sheet_name="Final Format")

                workbook = writer.book # Access the XlsxWriter workbook object.
                worksheet = writer.sheets["Final Format"] # Access the worksheet object.

                # Define header format.
                header_format = workbook.add_format({
                    "bold": True,
                    "bg_color": "#366092", # Dark blue background
                    "font_color": "white",
                    "border": 1,
                    "text_wrap": True # Allow text to wrap within cells
                })

                # Define a format for wrapping text in regular cells.
                wrap_format = workbook.add_format({"text_wrap": True})

                # Write custom headers and set column widths/formats.
                for idx, col in enumerate(result.columns):
                    worksheet.write(0, idx, col, header_format) # Write header row (row 0)
                    # Determine column width based on content, up to a max of 100.
                    max_width = min(100, max(len(col), result[col].astype(str).map(len).max()) + 2)
                    worksheet.set_column(idx, idx, max_width, wrap_format) # Set width and apply wrap format.

                # Freeze the first row so headers are always visible when scrolling.
                worksheet.freeze_panes(1, 0)

            self.status_var.set("Exported successfully!") # Update status message upon success.
        except Exception as e:
            # Catch any unexpected errors and display them in a message box.
            messagebox.showerror("Error", f"Failed: {e}")
            self.status_var.set(f"Error: {e}") # Update status bar with error.

    def run(self):
        """Starts the Tkinter event loop, making the GUI interactive."""
        self.root.mainloop()

# Entry point of the script.
if __name__ == "__main__":
    FinalExportGUI().run() # Create and run the GUI application.