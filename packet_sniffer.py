import psutil
import csv
import time
from datetime import datetime


CSV_FILE = "captured_connections.csv"


# ==========================================
# CREATE CSV FILE
# ==========================================

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
            "PID"
        ])


# ==========================================
# GET PROTOCOL
# ==========================================

def get_protocol(connection):

    if connection.type == 1:
        return "TCP"

    elif connection.type == 2:
        return "UDP"

    return "OTHER"


# ==========================================
# GET ADDRESS
# ==========================================

def get_address(address):

    if not address:
        return "-", "-"

    return address.ip, address.port


# ==========================================
# MONITOR
# ==========================================

def monitor(protocol_filter):

    displayed = set()

    total_connections = 0
    tcp_count = 0
    udp_count = 0

    remote_ips = set()

    start_time = time.time()

    print("\n==============================================")
    print("          NETWORK CONNECTION MONITOR")
    print("==============================================")

    print("Protocol :", protocol_filter)
    print("IPv4     : Enabled")
    print("IPv6     : Disabled")

    print("\nMonitoring started...")
    print("Open websites to generate connections.")
    print("Press CTRL + C to stop.\n")


    try:

        while True:

            connections = psutil.net_connections(
                kind="inet4"
            )


            for connection in connections:

                protocol = get_protocol(connection)


                # --------------------------------------
                # Protocol filter
                # --------------------------------------

                if protocol_filter != "ALL":

                    if protocol != protocol_filter:
                        continue


                # --------------------------------------
                # Get addresses
                # --------------------------------------

                local_ip, local_port = get_address(
                    connection.laddr
                )

                remote_ip, remote_port = get_address(
                    connection.raddr
                )

                status = connection.status
                pid = connection.pid


                # Ignore connections without remote IP

                if remote_ip == "-":
                    continue


                # --------------------------------------
                # Unique connection
                # --------------------------------------

                connection_id = (
                    protocol,
                    local_ip,
                    local_port,
                    remote_ip,
                    remote_port,
                    pid
                )


                if connection_id in displayed:
                    continue


                displayed.add(connection_id)


                # --------------------------------------
                # Statistics
                # --------------------------------------

                total_connections += 1

                remote_ips.add(remote_ip)


                if protocol == "TCP":

                    tcp_count += 1

                elif protocol == "UDP":

                    udp_count += 1


                current_time = datetime.now().strftime(
                    "%H:%M:%S"
                )


                # --------------------------------------
                # Display connection
                # --------------------------------------

                print("----------------------------------------------")

                print(
                    "Connection No :",
                    total_connections
                )

                print(
                    "Time          :",
                    current_time
                )

                print(
                    "Protocol      :",
                    protocol
                )

                print(
                    "Local IP      :",
                    local_ip
                )

                print(
                    "Local Port    :",
                    local_port
                )

                print(
                    "Remote IP     :",
                    remote_ip
                )

                print(
                    "Remote Port   :",
                    remote_port
                )

                print(
                    "Status        :",
                    status
                )

                print(
                    "PID           :",
                    pid
                )

                print("----------------------------------------------")


                # --------------------------------------
                # SAVE TO CSV
                # --------------------------------------

                with open(
                    CSV_FILE,
                    "a",
                    newline=""
                ) as file:

                    writer = csv.writer(file)

                    writer.writerow([
                        total_connections,
                        current_time,
                        protocol,
                        local_ip,
                        local_port,
                        remote_ip,
                        remote_port,
                        status,
                        pid
                    ])


            # --------------------------------------
            # Display statistics every cycle
            # --------------------------------------

            elapsed = int(time.time() - start_time)

            minutes = elapsed // 60
            seconds = elapsed % 60


            print(
                f"\r[STATISTICS] "
                f"Total: {total_connections} | "
                f"TCP: {tcp_count} | "
                f"UDP: {udp_count} | "
                f"Unique IPs: {len(remote_ips)} | "
                f"Time: {minutes:02d}:{seconds:02d}",
                end=""
            )


            time.sleep(3)


    except KeyboardInterrupt:


        print("\n\n==============================================")
        print("             MONITOR STOPPED")
        print("==============================================")


        elapsed = int(time.time() - start_time)

        minutes = elapsed // 60
        seconds = elapsed % 60


        print(
            "Total Connections :",
            total_connections
        )

        print(
            "TCP Connections   :",
            tcp_count
        )

        print(
            "UDP Connections   :",
            udp_count
        )

        print(
            "Unique Remote IPs :",
            len(remote_ips)
        )

        print(
            "Monitoring Time   :",
            f"{minutes:02d}:{seconds:02d}"
        )

        print(
            "CSV File          :",
            CSV_FILE
        )

        print("==============================================")


# ==========================================
# MAIN MENU
# ==========================================

def main():

    print("==============================================")
    print("          NETWORK CONNECTION MONITOR")
    print("==============================================")


    print("\nSelect protocol:")

    print("1. All Connections")
    print("2. TCP")
    print("3. UDP")


    choice = input(
        "\nEnter your choice (1-3): "
    )


    if choice == "1":

        protocol = "ALL"

    elif choice == "2":

        protocol = "TCP"

    elif choice == "3":

        protocol = "UDP"

    else:

        print("Invalid choice.")

        return


    create_csv()

    monitor(protocol)


# ==========================================
# START PROGRAM
# ==========================================

if __name__ == "__main__":

    main()
    