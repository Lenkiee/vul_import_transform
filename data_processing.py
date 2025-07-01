# data_processing.py
import pandas as pd
import re
# Import configuration variables from the centralized config.py
from config import ENV_MAP, HOSTNAME_APPLICATION_MAP, GROUP_KEY, VPR_ORDER

def create_final_format(df: pd.DataFrame, selected_envs: list, selected_vprs: list) -> pd.DataFrame | None:
    """
    Processes the input DataFrame to create the final JIRA-formatted data.

    This function applies environment and VPR filters, sorts the data,
    groups vulnerabilities by synopsis and VPR, and generates a JIRA ticket
    title and description for each group.

    Args:
        df (pd.DataFrame): The input DataFrame loaded from the Excel file.
        selected_envs (list): A list of environments selected by the user (e.g., ['Dev', 'PRD']).
        selected_vprs (list): A list of VPRs selected by the user (e.g., ['Critical', 'High']).

    Returns:
        pd.DataFrame: A DataFrame with 'Ticket_Title' and 'JIRA_Description' columns.
                      Returns None if no data is found after filtering.
    """
    # 1. Filter by selected environments
    # Map selected environment codes (e.g., "Dev") to their full names (e.g., "4. Development")
    allowed_envs = [ENV_MAP[env] for env in selected_envs]
    df = df[df['Environment'].isin(allowed_envs)]

    # 2. Filter by selected VPRs, if any were chosen by the user
    if selected_vprs:
        df = df[df['VPR'].isin(selected_vprs)]

    # If no data remains after filtering, return None to indicate no output
    if df.empty:
        return None

    # 3. Add a 'vpr_rank' column for custom sorting
    # Assigns a numerical rank based on VPR_ORDER. Unmapped VPRs get a high rank (99) to place them last.
    df['vpr_rank'] = df['VPR'].map(VPR_ORDER).fillna(99)

    # 4. Sort the DataFrame for consistent grouping and output order
    # First by the primary grouping key (Synopsis), then by the custom VPR rank.
    df = df.sort_values(by=[GROUP_KEY, 'vpr_rank'])

    # Initialize a list to store the dictionaries for the final output DataFrame rows
    rows = []

    # 5. Group the data to create individual JIRA tickets
    # Each group represents a unique combination of Synopsis and VPR, intended for one ticket.
    for (synopsis, vpr), group in df.groupby([GROUP_KEY, 'VPR']):
        highest_vpr_for_group = vpr # The VPR level for this specific group

        # Determine unique applications affected within this group
        group_applications = set()
        for _, row in group.iterrows():
            hostname = row['Hostname']
            # Look up the application based on the hostname using the imported map
            if hostname in HOSTNAME_APPLICATION_MAP:
                group_applications.add(HOSTNAME_APPLICATION_MAP[hostname])
            else:
                group_applications.add("N/A") # Mark as "N/A" if not found in the map

        # Clean up application names for the ticket title
        mapped_apps_list = sorted(list(group_applications))
        # If "N/A" is present alongside other valid applications, remove "N/A" for a cleaner title.
        if "N/A" in mapped_apps_list and len(mapped_apps_list) > 1:
            mapped_apps_list.remove("N/A")

        # Join unique application names for the title; default to "N/A" if none found
        app_string = ", ".join(mapped_apps_list) if mapped_apps_list else "N/A"

        # Construct the JIRA Ticket Title
        ticket_title = f"{app_string} - {highest_vpr_for_group} - {group.iloc[0]['Vulnerability']}"

        # Initialize the JIRA Description string
        description = "Affected Hosts:\n"
        
        # Iterate through each affected host in the current group to build its detailed description
        for _, row in group.iterrows():
            # Safely retrieve 'Plugin Text', clean HTML tags, and default to 'N/A'
            plugin_text = re.sub(r"</?plugin_output>", "", row.get('Plugin Text', 'N/A'), flags=re.IGNORECASE).strip()
            first_discovered = row.get('First Discovered', 'N/A')
            cve = row.get('CVE', 'N/A')

            # Append host-specific details to the description
            description += (
                f"* Host: {row['Hostname']}\n"
                f"  Environment: {row['Environment']}\n"
                f"  Role: {row['Role']}\n"
                f"  Remediation: {row['Remediation (Solution)']}\n"
                f"  First Discovered: {first_discovered}\n"
                f"  CVE: {cve}\n"
                f"  Plugin Text:\n{plugin_text}\n\n"
                # Add more fields to the description here if needed, following the same pattern:
                # f"  NewField: {row.get('New Excel Column Name', 'N/A')}\n"
            )

        # Add the generated ticket title and description to the list of rows
        rows.append({"Ticket_Title": ticket_title, "JIRA_Description": description})

    # Convert the list of dictionaries into a pandas DataFrame for output
    return pd.DataFrame(rows)