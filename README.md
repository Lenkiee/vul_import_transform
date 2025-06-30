JIRA Vulnerability Export Tool
This Python script provides a graphical user interface (GUI) to transform raw vulnerability data from an Excel spreadsheet into a structured format suitable for creating JIRA tickets. It allows users to filter data by environment and VPR (Vulnerability Priority Rating) and then generates an Excel file with "Ticket_Title" and detailed "JIRA_Description" columns for each identified vulnerability group and affected host.

Features
GUI-based File Selection: Easily select your input Excel vulnerability report.

Environment Filtering: Filter vulnerabilities based on predefined environments (Development, Test, Acceptance, Production).

VPR Filtering: Optionally filter by specific VPR ratings (Critical, High, Medium, Low, Undefined).

Automated Ticket Title Generation: Creates concise JIRA ticket titles based on application, VPR, and vulnerability.

Detailed JIRA Description: Generates comprehensive descriptions for each JIRA ticket, including:

Affected Hostnames

Environment

Role

Remediation Solution

First Discovered Date

Associated CVEs (Common Vulnerabilities and Exposures)

Plugin Text/Output

Excel Output: Exports the transformed data into a new Excel file, formatted with proper headers and text wrapping.

Error Handling: Includes checks for missing required columns in the input file and provides user-friendly messages.

Getting Started
Prerequisites
Before running the script, ensure you have Python installed (version 3.7 or higher recommended). You'll also need the following Python libraries:

pandas

openpyxl (often installed as a dependency for pandas, but good to check)

tkinter (usually comes pre-installed with Python)

xlsxwriter (for advanced Excel formatting)

You can install the necessary libraries using pip:

Bash

pip install pandas openpyxl xlsxwriter
Installation
Save the Script: Save the provided Python code as a .py file (e.g., jira_exporter.py) in a folder.

Place Your Excel Files: Put your Excel vulnerability reports (e.g., vulnerability_report.xlsx) in the same folder as the script. The GUI will automatically detect and list them.

Usage
Run the Script: Open a terminal or command prompt, navigate to the directory where you saved the script, and run it:

Bash

python jira_exporter.py
Select Excel File: From the dropdown menu, choose the Excel file you wish to process.

Select Environments: Check the boxes next to the environments you want to include in your output (e.g., Dev, PRD).

Filter VPR (Optional): Check the boxes next to the VPR ratings you want to include. If no VPRs are selected, all will be included.

Export: Click the "Export Final Format" button.

Save Output File: A "Save As" dialog will appear. Choose a location and filename for your new Excel file.

The output Excel file will contain two columns: Ticket_Title and JIRA_Description.

Input Excel File Format
The script expects your input Excel file to have the following columns precisely named (case-sensitive):

Hostname

Vulnerability

Remediation (Solution)

Role

Environment

Synopsis

Plugin Text

VPR

VPR Score

First Discovered

CVE

If any of these columns are missing, the script will show an error message.

Configuration
The script contains internal mappings and settings that can be customized:

ENV_MAP: Maps internal environment shortcodes (e.g., "Dev") to more descriptive JIRA-friendly names (e.g., "4. Development"). Modify this dictionary to match your organization's environment naming conventions.

APPLICATION_MAP: Maps raw application names from your report to standardized application names used in JIRA titles. Adjust this to consolidate or rename applications as needed.

GROUP_KEY: Defines the column used to group vulnerabilities into single JIRA tickets (currently Synopsis).

VPR_ORDER: Defines the sorting order for VPRs. Do not change the values (0, 1, 2, etc.) as they define the sorting priority. Only modify the keys (e.g., "Undefined", "Critical") if your VPR names differ.

How It Works
The core logic resides in the create_final_format function:

Filtering: It first filters the DataFrame based on the selected environments and VPRs.

Sorting: Data is sorted by Synopsis and then by VPR rank to ensure consistent grouping and prioritisation.

Grouping: The script groups rows by Synopsis and VPR. This ensures that vulnerabilities with the same synopsis but different VPRs (e.g., a "Critical" instance on one host and a "High" instance on another, for the same vulnerability synopsis) will generate separate JIRA tickets, which is often desired for prioritization.

Title and Description Generation: For each group:

A Ticket_Title is created by combining mapped applications, the highest VPR in the group, and the vulnerability name.

A JIRA_Description is built iteratively, listing each affected host with its environment, role, remediation, first discovered date, CVEs, and relevant plugin text.

GUI Integration: The FinalExportGUI class handles the user interface, file selection, filter options, and the export process, providing a user-friendly experience.

Troubleshooting
"Missing Columns" Error: Check your input Excel file's column headers carefully. They must exactly match the names listed in the "Input Excel File Format" section above (case-sensitive).

"No Data after filtering" Error: This means your selected environments and VPR filters resulted in an empty dataset. Try broadening your filter selections.

Script Doesn't Start: Ensure you have installed all required libraries (pandas, openpyxl, xlsxwriter). Also, verify your Python installation.

Plugin Text Formatting: The script attempts to clean HTML-like tags (<plugin_output>) from the Plugin Text. If your plugin text contains other unusual characters or formatting, you might need to adjust the re.sub line in create_final_format.