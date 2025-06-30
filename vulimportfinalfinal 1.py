import os
import pandas as pd
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import warnings
import re

# Suppress pandas warnings
warnings.simplefilter("ignore", UserWarning)

# Environment and application mappings
ENV_MAP = {
    "Dev": "4. Development",
    "TST": "3. Test",
    "ACP": "2. Acceptance",
    "PRD": "1. Production"
}

APPLICATION_MAP = {
    "OSX Application Server": "OneSumX",
    "OSX application": "OneSumX",
    "OneSumX SQL": "OneSumX",
    "Database AnaCredit": "Anacredit",
    "Application Server RegPro": "RegPro",
    "RegPro": "RegPro"
}

# Key to group by
GROUP_KEY = "Synopsis"

# Expected columns
REQUIRED_COLUMNS = [
    'Hostname', 'Vulnerability', 'Remediation (Solution)', 'Role', 'Environment',
    'Synopsis', 'Plugin Text', 'VPR', 'VPR Score'
]

# Fixed VPR order - now exactly matching your Excel file
VPR_ORDER = {
    "Undefined": 0, "Critical": 1, "High": 2, "Medium": 3, "Low": 4
}


def create_final_format(df, selected_envs, selected_vprs):
    # Filter environments
    allowed_envs = [ENV_MAP[env] for env in selected_envs]
    df = df[df['Environment'].isin(allowed_envs)]

    # Filter VPR
    if selected_vprs:
        df = df[df['VPR'].isin(selected_vprs)]

    if df.empty:
        messagebox.showwarning("No Data", "No rows found after applying filters.")
        return None

    # Sort by synopsis and VPR rank
    df['vpr_rank'] = df['VPR'].map(VPR_ORDER).fillna(99)
    df = df.sort_values(by=[GROUP_KEY, 'vpr_rank'])

    # Group by synopsis AND VPR to force separation of critical vs high
    rows = []
    for (synopsis, vpr), group in df.groupby([GROUP_KEY, 'VPR']):
        highest_vpr = vpr  # because we're grouping by it, it's the same for all in this group

        # Collect roles & applications (Application might not exist in some files)
        all_values = group['Role'].dropna().tolist()
        if 'Application' in group.columns:
            all_values.extend(group['Application'].dropna().tolist())

        mapped_apps = sorted(set(APPLICATION_MAP.get(val, val) for val in all_values))
        app_string = ", ".join(mapped_apps) if mapped_apps else "N/A"

        ticket_title = f"{app_string} - {highest_vpr} - {group.iloc[0]['Vulnerability']}"

        description = "Affected Hosts:\n"
        for _, row in group.iterrows():
            plugin_text = re.sub(r"</?plugin_output>", "", row.get('Plugin Text', 'N/A'), flags=re.IGNORECASE).strip()

            description += (f"* Host: {row['Hostname']}\n"
                            f"  Environment: {row['Environment']}\n"
                            f"  Role: {row['Role']}\n"
                            f"  Remediation: {row['Remediation (Solution)']}\n"
                            f"  Plugin Text:\n{plugin_text}\n\n")

        rows.append({"Ticket_Title": ticket_title, "JIRA_Description": description})

    return pd.DataFrame(rows)


class FinalExportGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Final Format Exporter")
        self.root.geometry("600x400")

        self.file_path = None
        self.env_selections = {}
        self.vpr_selections = {}

        self._setup_ui()

    def _setup_ui(self):
        frame = ttk.Frame(self.root, padding=10)
        frame.pack(fill="both", expand=True)

        file_frame = ttk.LabelFrame(frame, text="Select Excel File", padding=10)
        file_frame.pack(fill="x", pady=5)

        self.file_var = tk.StringVar()
        self.file_dropdown = ttk.Combobox(file_frame, textvariable=self.file_var, state="readonly", width=50)
        self.file_dropdown.pack(side="left", padx=5)

        self._populate_files()

        self.file_dropdown.bind('<<ComboboxSelected>>', self._file_selected)

        env_frame = ttk.LabelFrame(frame, text="Select Environments", padding=10)
        env_frame.pack(fill="x", pady=5)

        for env in ENV_MAP:
            var = tk.BooleanVar()
            ttk.Checkbutton(env_frame, text=env, variable=var).pack(side="left", padx=5)
            self.env_selections[env] = var

        vpr_frame = ttk.LabelFrame(frame, text="VPR Filter", padding=10)
        vpr_frame.pack(fill="x", pady=5)

        for vpr in VPR_ORDER:
            var = tk.BooleanVar()
            ttk.Checkbutton(vpr_frame, text=vpr, variable=var).pack(side="left", padx=5)
            self.vpr_selections[vpr] = var

        ttk.Button(frame, text="Export Final Format", command=self._export).pack(fill="x", pady=10)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(frame, textvariable=self.status_var).pack(fill="x", pady=5)

    def _populate_files(self):
        folder = os.path.dirname(os.path.realpath(__file__))
        files = [f for f in os.listdir(folder) if f.endswith('.xlsx')]
        self.file_dropdown['values'] = files

    def _file_selected(self, event):
        folder = os.path.dirname(os.path.realpath(__file__))
        self.file_path = os.path.join(folder, self.file_var.get())

    def _export(self):
        if not self.file_path:
            messagebox.showerror("Error", "Please select an Excel file.")
            return

        try:
            df = pd.read_excel(self.file_path)

            missing_cols = [col for col in REQUIRED_COLUMNS if col not in df.columns]
            if missing_cols:
                messagebox.showerror("Missing Columns", f"Missing required columns: {', '.join(missing_cols)}")
                return

            selected_envs = [env for env, var in self.env_selections.items() if var.get()]
            selected_vprs = [vpr for vpr, var in self.vpr_selections.items() if var.get()]

            if not selected_envs:
                messagebox.showwarning("Missing Selection", "Select at least one environment.")
                return

            self.status_var.set("Processing...")
            self.root.update()

            result = create_final_format(df, selected_envs, selected_vprs)

            if result is None:
                self.status_var.set("No data after filtering.")
                return

            save_path = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx")])
            if not save_path:
                return

            with pd.ExcelWriter(save_path, engine="xlsxwriter") as writer:
                result.to_excel(writer, index=False, startrow=1, header=False, sheet_name="Final Format")

                workbook = writer.book
                worksheet = writer.sheets["Final Format"]

                header_format = workbook.add_format({
                    "bold": True,
                    "bg_color": "#366092",
                    "font_color": "white",
                    "border": 1,
                    "text_wrap": True
                })

                wrap_format = workbook.add_format({"text_wrap": True})

                for idx, col in enumerate(result.columns):
                    worksheet.write(0, idx, col, header_format)
                    max_width = min(100, max(len(col), result[col].astype(str).map(len).max()) + 2)
                    worksheet.set_column(idx, idx, max_width, wrap_format)

                worksheet.freeze_panes(1, 0)

            self.status_var.set("Exported successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed: {e}")

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    FinalExportGUI().run()
