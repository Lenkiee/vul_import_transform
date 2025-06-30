JIRA Vulnerability Exporter
This Python script helps you transform raw vulnerability scan Excel reports into a structured format, suitable for creating JIRA tickets. It groups vulnerabilities by Synopsis, enriches data, and allows filtering by environment and VPR.

How it Works
The script provides a simple graphical user interface (GUI):

Input Excel: It reads an Excel file containing vulnerability data.

Configuration: It uses predefined mappings (HOSTNAME_APPLICATION_MAP) to link hostnames to applications.

Filtering: You select desired environments (e.g., Dev, TST, PRD) and VPR levels (e.g., Critical, High) via checkboxes.

Grouping: Vulnerabilities are grouped by their Synopsis and VPR level. Each unique group generates one JIRA ticket.

Output: It produces a new Excel file with Ticket_Title and JIRA_Description columns, formatted for easy import into JIRA or similar systems.

Getting Started
1. Prerequisites
Python 3.x installed.

Required libraries: pandas, openpyxl (needed by pandas for .xlsx files), xlsxwriter (for formatting output Excel).

2. Setup (Recommended: Virtual Environment)
Using a virtual environment prevents conflicts with other Python projects.

Open Visual Studio Code.

Open the folder containing this script (.py file).

Open the Integrated Terminal (Terminal > New Terminal or `Ctrl+Shift+``).

Create a virtual environment:

Bash

python -m venv venv
Activate the virtual environment:

Windows (Command Prompt/PowerShell):

Bash

.\venv\Scripts\activate
macOS/Linux (Bash/Zsh):

Bash

source venv/bin/activate
You should see (venv) at the start of your terminal prompt, indicating the virtual environment is active.

Install dependencies:
Create a requirements.txt file in the same directory as the script with these contents:

pandas
openpyxl
xlsxwriter
Then, in your activated terminal, run:

Bash

pip install -r requirements.txt
3. Prepare Your Data
Place your Excel report (.xlsx file) in the same folder as the script.

Verify Column Names: Ensure your Excel report contains all columns listed in REQUIRED_COLUMNS within the script. Missing mandatory columns will cause an error.

Configuration (Edit the Script)
Before running, you must customize the following directly in the jira_exporter.py file:

HOSTNAME_APPLICATION_MAP: This dictionary is the only source for mapping hostnames to applications.

Edit this section to include all your hostnames and their corresponding application names.

Example: "SVNIBCSQLD027": "OneSumX",

REQUIRED_COLUMNS: If your input Excel file introduces new columns that must be present, add their exact names to this list.

Running the Script
Ensure your virtual environment is active (see Step 2 above).

Run the script from your VS Code terminal:

Bash

python your_script_name.py
(Replace your_script_name.py with the actual file name if you renamed it).

A GUI window will appear.

Using the GUI
Select Excel File: Choose your vulnerability report from the dropdown menu. Only .xlsx files in the same directory will appear.

Select Environments: Check the boxes for the environments you want to include (e.g., PRD, TST).

VPR Filter: (Optional) Check the VPR levels you want to include (e.g., Critical, High). If no VPRs are selected, all will be included.

Click "Export Final Format":

The script will process the data.

A "Save As" dialog will appear. Choose a location and name for your output Excel file.

Advanced Customization
Adding New Columns to the Output Excel
The script currently outputs Ticket_Title and JIRA_Description. To add more columns to the final Excel:

Locate rows.append(...): Find the line rows.append({"Ticket_Title": ticket_title, "JIRA_Description": description}) in the create_final_format function.

Add Key-Value Pairs: Insert new entries into this dictionary.

"New_Column_Name": value_for_this_ticket

value_for_this_ticket can be:

Data from your input Excel: row.get('YourInputColumnName', 'N/A')

A calculated value.

A fixed string.

Adding More Details to JIRA_Description
To include more data points within the JIRA_Description text:

Locate the description += (...) block: Find the multi-line f-string that builds the description, typically within the for _, row in group.iterrows(): loop.

Access Data: Use row.get('YourColumnName', 'N/A') to safely retrieve data from a specific column for each host.

Insert into String: Add a new line to the f-string, embedding the retrieved value.

Example: f" New Detail: {new_detail_variable}\n"