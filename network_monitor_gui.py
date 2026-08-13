import tkinter as tk
from tkinter import ttk, messagebox
import psutil
import threading
import csv
import time
from datetime import datetime

import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


# ============================================================
# SETTINGS
# ============================================================

CSV_FILE = "captured_connections.csv"

monitoring = False

seen_connections = set()
connections_data = []

total_connections = 0
tcp_count = 0
udp_count = 0

remote_ips = set()

syn_sent_count = {}


# ============================================================
# CREATE CSV
# ============================================================

def create_csv():

    with open(CSV_FILE, "w", newline="") as file:

        writer = csv.writer(file)

        writer.writerow([
            "No",
            "Time",
            "Protocol",
            "Local IP",
            "Local Port",
            "Remote IP",
            "Remote Port",
            "Status",
            "PID",
            "Risk"
        ])


# ============================================================
# PROTOCOL
# ============================================================

def get_protocol(connection):

    if connection.type == 1:
        return "TCP"

    elif connection.type == 2:
        return "UDP"

    return "OTHER"


# ============================================================
# ADDRESS
# ============================================================

def get_address(address):

    if not address:
        return "-", "-"

    try:
        return address.ip, address.port
    except AttributeError:
        return "-", "-"


# ============================================================
# RISK ANALYSIS
# ============================================================

def analyze_risk(
    protocol,
    remote_ip,
    remote_port,
    status
):

    normal_ports = {
        53,
        80,
        443,
        22,
        123
    }

    unusual_ports = {
        4444,
        5555,
        6666,
        1337,
        31337
    }

    # No remote address is normal for
    # many UDP sockets.
    if remote_port == "-":

        if protocol == "UDP":
            return "NORMAL"

        return "WARNING"

    # Educational unusual-port rule

    if remote_port in unusual_ports:

        return "SUSPICIOUS"

    # SYN_SENT rule

    if status == "SYN_SENT":

        if remote_ip not in syn_sent_count:

            syn_sent_count[remote_ip] = 0

        syn_sent_count[remote_ip] += 1

        if syn_sent_count[remote_ip] >= 5:

            return "WARNING"

    # Common ports

    if remote_port in normal_ports:

        return "NORMAL"

    return "WARNING"


# ============================================================
# START MONITORING
# ============================================================

def start_monitoring():

    global monitoring

    if monitoring:
        return

    create_csv()

    monitoring = True

    start_button.config(
        state=tk.DISABLED
    )

    stop_button.config(
        state=tk.NORMAL
    )

    status_label.config(
        text="● Monitoring..."
    )

    thread = threading.Thread(
        target=monitor_connections,
        daemon=True
    )

    thread.start()


# ============================================================
# STOP MONITORING
# ============================================================

def stop_monitoring():

    global monitoring

    monitoring = False

    start_button.config(
        state=tk.NORMAL
    )

    stop_button.config(
        state=tk.DISABLED
    )

    status_label.config(
        text="● Stopped"
    )


# ============================================================
# MONITOR CONNECTIONS
# ============================================================

def monitor_connections():

    global total_connections
    global tcp_count
    global udp_count

    while monitoring:

        try:

            # IMPORTANT:
            # inet includes IPv4 + IPv6
            # and both TCP + UDP

            connections = psutil.net_connections(
                kind="inet"
            )

            selected_protocol = protocol_combo.get()

            for connection in connections:

                protocol = get_protocol(
                    connection
                )

                # ----------------------------------------
                # FILTER
                # ----------------------------------------

                if selected_protocol != "ALL":

                    if protocol != selected_protocol:

                        continue

                # ----------------------------------------
                # LOCAL ADDRESS
                # ----------------------------------------

                local_ip, local_port = get_address(
                    connection.laddr
                )

                # ----------------------------------------
                # REMOTE ADDRESS
                # ----------------------------------------

                remote_ip, remote_port = get_address(
                    connection.raddr
                )

                status = connection.status

                pid = connection.pid

                # ----------------------------------------
                # IMPORTANT:
                # DO NOT SKIP UDP WITHOUT REMOTE IP
                # ----------------------------------------

                # UDP can legitimately have:
                #
                # Remote IP = -
                # Remote Port = -
                #
                # because UDP is connectionless.

                # ----------------------------------------
                # UNIQUE CONNECTION
                # ----------------------------------------

                connection_id = (
                    protocol,
                    local_ip,
                    local_port,
                    remote_ip,
                    remote_port,
                    status,
                    pid
                )

                if connection_id in seen_connections:

                    continue

                seen_connections.add(
                    connection_id
                )

                # ----------------------------------------
                # STATISTICS
                # ----------------------------------------

                total_connections += 1

                if remote_ip != "-":

                    remote_ips.add(
                        remote_ip
                    )

                if protocol == "TCP":

                    tcp_count += 1

                elif protocol == "UDP":

                    udp_count += 1

                # ----------------------------------------
                # TIME
                # ----------------------------------------

                current_time = datetime.now().strftime(
                    "%H:%M:%S"
                )

                # ----------------------------------------
                # RISK
                # ----------------------------------------

                risk = analyze_risk(
                    protocol,
                    remote_ip,
                    remote_port,
                    status
                )

                # ----------------------------------------
                # ROW
                # ----------------------------------------

                row = (
                    total_connections,
                    current_time,
                    protocol,
                    local_ip,
                    local_port,
                    remote_ip,
                    remote_port,
                    status,
                    pid if pid is not None else "-",
                    risk
                )

                connections_data.append(
                    row
                )

                # ----------------------------------------
                # UPDATE GUI
                # ----------------------------------------

                root.after(
                    0,
                    refresh_table
                )

                root.after(
                    0,
                    update_statistics
                )

                root.after(
                    0,
                    update_risk_statistics
                )

                # ----------------------------------------
                # SAVE CSV
                # ----------------------------------------

                with open(
                    CSV_FILE,
                    "a",
                    newline=""
                ) as file:

                    writer = csv.writer(file)

                    writer.writerow(row)

        except Exception as error:

            print(
                "Monitoring Error:",
                error
            )

        time.sleep(3)


# ============================================================
# REFRESH TABLE
# ============================================================

def refresh_table():

    for item in table.get_children():

        table.delete(item)

    search_text = search_entry.get().lower().strip()

    selected_protocol = protocol_combo.get()

    for row in connections_data:

        # ----------------------------------------
        # Protocol filtering
        # ----------------------------------------

        if selected_protocol != "ALL":

            if row[2] != selected_protocol:

                continue

        # ----------------------------------------
        # Search filtering
        # ----------------------------------------

        row_text = " ".join(
            str(value).lower()
            for value in row
        )

        if (
            search_text != ""
            and search_text not in row_text
        ):

            continue

        # ----------------------------------------
        # Risk color
        # ----------------------------------------

        risk = row[9]

        if risk == "SUSPICIOUS":

            table.insert(
                "",
                "end",
                values=row,
                tags=("suspicious",)
            )

        elif risk == "WARNING":

            table.insert(
                "",
                "end",
                values=row,
                tags=("warning",)
            )

        else:

            table.insert(
                "",
                "end",
                values=row,
                tags=("normal",)
            )

    children = table.get_children()

    if children:

        table.yview_moveto(1)


# ============================================================
# SEARCH
# ============================================================

def search_connections(event=None):

    refresh_table()


# ============================================================
# CLEAR SEARCH
# ============================================================

def clear_search():

    search_entry.delete(
        0,
        tk.END
    )

    refresh_table()


# ============================================================
# UPDATE STATISTICS
# ============================================================

def update_statistics():

    total_label.config(
        text=f"TOTAL\n{total_connections}"
    )

    tcp_label.config(
        text=f"TCP\n{tcp_count}"
    )

    udp_label.config(
        text=f"UDP\n{udp_count}"
    )

    ip_label.config(
        text=f"UNIQUE IPs\n{len(remote_ips)}"
    )


# ============================================================
# RISK STATISTICS
# ============================================================

def update_risk_statistics():

    normal = 0
    warning = 0
    suspicious = 0

    for row in connections_data:

        risk = row[9]

        if risk == "NORMAL":

            normal += 1

        elif risk == "WARNING":

            warning += 1

        elif risk == "SUSPICIOUS":

            suspicious += 1

    normal_label.config(
        text=f"NORMAL\n{normal}"
    )

    warning_label.config(
        text=f"WARNING\n{warning}"
    )

    suspicious_label.config(
        text=f"SUSPICIOUS\n{suspicious}"
    )


# ============================================================
# CLEAR TABLE
# ============================================================

def clear_table():

    global total_connections
    global tcp_count
    global udp_count

    for item in table.get_children():

        table.delete(item)

    connections_data.clear()
    seen_connections.clear()
    remote_ips.clear()
    syn_sent_count.clear()

    total_connections = 0
    tcp_count = 0
    udp_count = 0

    update_statistics()
    update_risk_statistics()


# ============================================================
# EXPORT CSV
# ============================================================

def export_csv():

    try:

        if not connections_data:

            messagebox.showwarning(
                "No Data",
                "There are no connections to export."
            )

            return

        export_file = "network_report.csv"

        with open(
            export_file,
            "w",
            newline=""
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                "No",
                "Time",
                "Protocol",
                "Local IP",
                "Local Port",
                "Remote IP",
                "Remote Port",
                "Status",
                "PID",
                "Risk"
            ])

            for row in connections_data:

                writer.writerow(row)

        messagebox.showinfo(
            "Export Successful",
            "Network report exported successfully!\n\n"
            "File: network_report.csv"
        )

    except Exception as error:

        messagebox.showerror(
            "Export Error",
            str(error)
        )


# ============================================================
# DASHBOARD
# ============================================================

def show_dashboard():

    if not connections_data:

        messagebox.showwarning(
            "No Data",
            "Start monitoring first."
        )

        return

    normal = 0
    warning = 0
    suspicious = 0

    for row in connections_data:

        if row[9] == "NORMAL":
            normal += 1

        elif row[9] == "WARNING":
            warning += 1

        elif row[9] == "SUSPICIOUS":
            suspicious += 1

    dashboard = tk.Toplevel(root)

    dashboard.title(
        "Network Monitoring Dashboard"
    )

    dashboard.geometry(
        "950x700"
    )

    dashboard.minsize(
        800,
        600
    )

    # ----------------------------------------
    # TITLE
    # ----------------------------------------

    title = tk.Label(
        dashboard,
        text="NETWORK MONITORING DASHBOARD",
        font=("Arial", 20, "bold")
    )

    title.pack(
        pady=15
    )

    # ----------------------------------------
    # STATISTICS
    # ----------------------------------------

    stats = tk.Frame(
        dashboard
    )

    stats.pack(
        pady=10
    )

    statistics = [
        ("TOTAL", total_connections),
        ("TCP", tcp_count),
        ("UDP", udp_count),
        ("UNIQUE IPs", len(remote_ips))
    ]

    for index, (name, value) in enumerate(statistics):

        tk.Label(
            stats,
            text=f"{name}\n{value}",
            font=("Arial", 13, "bold"),
            width=15
        ).grid(
            row=0,
            column=index,
            padx=10
        )

    # ----------------------------------------
    # FIGURE
    # ----------------------------------------

    figure = plt.Figure(
        figsize=(9, 5),
        dpi=100
    )

    # ----------------------------------------
    # TCP / UDP
    # ----------------------------------------

    chart1 = figure.add_subplot(
        121
    )

    chart1.bar(
        ["TCP", "UDP"],
        [tcp_count, udp_count]
    )

    chart1.set_title(
        "TCP vs UDP Connections"
    )

    chart1.set_ylabel(
        "Number of Connections"
    )

    # ----------------------------------------
    # RISK
    # ----------------------------------------

    chart2 = figure.add_subplot(
        122
    )

    chart2.bar(
        ["NORMAL", "WARNING", "SUSPICIOUS"],
        [normal, warning, suspicious]
    )

    chart2.set_title(
        "Connection Risk Analysis"
    )

    chart2.set_ylabel(
        "Number of Connections"
    )

    chart2.tick_params(
        axis="x",
        rotation=20
    )

    figure.tight_layout()

    # ----------------------------------------
    # CANVAS
    # ----------------------------------------

    canvas = FigureCanvasTkAgg(
        figure,
        master=dashboard
    )

    canvas.draw()

    canvas.get_tk_widget().pack(
        fill="both",
        expand=True,
        padx=20,
        pady=20
    )

    # ----------------------------------------
    # CLOSE DASHBOARD
    # ----------------------------------------

    def close_dashboard():

        plt.close(
            figure
        )

        dashboard.destroy()

    dashboard.protocol(
        "WM_DELETE_WINDOW",
        close_dashboard
    )


# ============================================================
# CLOSE APPLICATION
# ============================================================

def close_application():

    global monitoring

    monitoring = False

    root.destroy()


# ============================================================
# MAIN WINDOW
# ============================================================

root = tk.Tk()

root.title(
    "Network Connection Monitor"
)

root.geometry(
    "1450x820"
)

root.minsize(
    1100,
    650
)


# ============================================================
# TITLE
# ============================================================

title = tk.Label(
    root,
    text="NETWORK CONNECTION MONITOR",
    font=("Arial", 22, "bold")
)

title.pack(
    pady=15
)


# ============================================================
# CONTROL FRAME
# ============================================================

control_frame = tk.Frame(
    root
)

control_frame.pack(
    pady=5
)


# ============================================================
# PROTOCOL
# ============================================================

tk.Label(
    control_frame,
    text="Protocol:",
    font=("Arial", 12)
).grid(
    row=0,
    column=0,
    padx=5
)


protocol_combo = ttk.Combobox(
    control_frame,
    values=[
        "ALL",
        "TCP",
        "UDP"
    ],
    state="readonly",
    width=10
)

protocol_combo.set(
    "ALL"
)

protocol_combo.grid(
    row=0,
    column=1,
    padx=5
)

protocol_combo.bind(
    "<<ComboboxSelected>>",
    lambda event: refresh_table()
)


# ============================================================
# START
# ============================================================

start_button = tk.Button(
    control_frame,
    text="START",
    width=12,
    command=start_monitoring
)

start_button.grid(
    row=0,
    column=2,
    padx=8
)


# ============================================================
# STOP
# ============================================================

stop_button = tk.Button(
    control_frame,
    text="STOP",
    width=12,
    command=stop_monitoring,
    state=tk.DISABLED
)

stop_button.grid(
    row=0,
    column=3,
    padx=8
)


# ============================================================
# CLEAR
# ============================================================

clear_button = tk.Button(
    control_frame,
    text="CLEAR",
    width=12,
    command=clear_table
)

clear_button.grid(
    row=0,
    column=4,
    padx=8
)


# ============================================================
# EXPORT
# ============================================================

export_button = tk.Button(
    control_frame,
    text="EXPORT CSV",
    width=12,
    command=export_csv
)

export_button.grid(
    row=0,
    column=5,
    padx=8
)


# ============================================================
# DASHBOARD
# ============================================================

dashboard_button = tk.Button(
    control_frame,
    text="DASHBOARD",
    width=12,
    command=show_dashboard
)

dashboard_button.grid(
    row=0,
    column=6,
    padx=8
)


# ============================================================
# SEARCH
# ============================================================

search_frame = tk.Frame(
    root
)

search_frame.pack(
    pady=10
)


tk.Label(
    search_frame,
    text="Search:",
    font=("Arial", 12)
).pack(
    side="left",
    padx=5
)


search_entry = tk.Entry(
    search_frame,
    width=45,
    font=("Arial", 11)
)

search_entry.pack(
    side="left",
    padx=5
)

search_entry.bind(
    "<KeyRelease>",
    search_connections
)


tk.Button(
    search_frame,
    text="CLEAR SEARCH",
    command=clear_search
).pack(
    side="left",
    padx=5
)


# ============================================================
# SEARCH HELP
# ============================================================

tk.Label(
    root,
    text="Search by IP address, port, protocol, status, PID or risk",
    font=("Arial", 9)
).pack()


# ============================================================
# STATUS
# ============================================================

status_label = tk.Label(
    root,
    text="● Stopped",
    font=("Arial", 11)
)

status_label.pack(
    pady=5
)


# ============================================================
# TABLE FRAME
# ============================================================

table_frame = tk.Frame(
    root
)

table_frame.pack(
    fill="both",
    expand=True,
    padx=15,
    pady=10
)


# ============================================================
# TABLE
# ============================================================

columns = (
    "No",
    "Time",
    "Protocol",
    "Local IP",
    "Local Port",
    "Remote IP",
    "Remote Port",
    "Status",
    "PID",
    "Risk"
)

table = ttk.Treeview(
    table_frame,
    columns=columns,
    show="headings"
)


for column in columns:

    table.heading(
        column,
        text=column
    )

    table.column(
        column,
        width=125
    )


# ============================================================
# RISK COLORS
# ============================================================

table.tag_configure(
    "normal",
    foreground="green"
)

table.tag_configure(
    "warning",
    foreground="orange"
)

table.tag_configure(
    "suspicious",
    foreground="red"
)


# ============================================================
# SCROLLBAR
# ============================================================

scrollbar = ttk.Scrollbar(
    table_frame,
    orient="vertical",
    command=table.yview
)

table.configure(
    yscrollcommand=scrollbar.set
)

table.pack(
    side="left",
    fill="both",
    expand=True
)

scrollbar.pack(
    side="right",
    fill="y"
)


# ============================================================
# STATISTICS
# ============================================================

stats_frame = tk.Frame(
    root
)

stats_frame.pack(
    pady=8
)


total_label = tk.Label(
    stats_frame,
    text="TOTAL\n0",
    font=("Arial", 12, "bold"),
    width=13
)

total_label.grid(
    row=0,
    column=0,
    padx=8
)


tcp_label = tk.Label(
    stats_frame,
    text="TCP\n0",
    font=("Arial", 12, "bold"),
    width=13
)

tcp_label.grid(
    row=0,
    column=1,
    padx=8
)


udp_label = tk.Label(
    stats_frame,
    text="UDP\n0",
    font=("Arial", 12, "bold"),
    width=13
)

udp_label.grid(
    row=0,
    column=2,
    padx=8
)


ip_label = tk.Label(
    stats_frame,
    text="UNIQUE IPs\n0",
    font=("Arial", 12, "bold"),
    width=13
)

ip_label.grid(
    row=0,
    column=3,
    padx=8
)


normal_label = tk.Label(
    stats_frame,
    text="NORMAL\n0",
    font=("Arial", 12, "bold"),
    width=13
)

normal_label.grid(
    row=0,
    column=4,
    padx=8
)


warning_label = tk.Label(
    stats_frame,
    text="WARNING\n0",
    font=("Arial", 12, "bold"),
    width=13
)

warning_label.grid(
    row=0,
    column=5,
    padx=8
)


suspicious_label = tk.Label(
    stats_frame,
    text="SUSPICIOUS\n0",
    font=("Arial", 12, "bold"),
    width=13
)

suspicious_label.grid(
    row=0,
    column=6,
    padx=8
)


# ============================================================
# CLOSE EVENT
# ============================================================

root.protocol(
    "WM_DELETE_WINDOW",
    close_application
)


# ============================================================
# START GUI
# ============================================================

root.mainloop()