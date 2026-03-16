#!/usr/bin/env python3
"""
PowerScale Isilon Syslog Generator
Sends RFC5424 formatted syslog messages with PowerScale audit format
to an OTel collector syslog receiver.

Format: Pipe-delimited structured audit logs matching PowerScale OneFS format
Fields: EventID|UserSID|UserID|ZoneName|ZoneID|clientIPAddr|Protocol|Operation|ntStatus|desiredAccess|isDirectory|createResult|inode|filename
"""

import socket
import time
from datetime import datetime, timezone
import random
import ssl

# Configuration
SYSLOG_SERVER = "localhost"
SYSLOG_PORT = 54526
PROTOCOL = "TCP"  # Can also be "UDP"
# TODO: Solve TLS certificate issues to enable secure syslog transport.
USE_TLS = False  # RFC 5425: TLS Transport of Syslog
VERIFY_CERT = False  # Set to True if using valid certificates

# RFC5424 Severity levels
SEVERITY = {
    "emergency": 0,
    "alert": 1,
    "critical": 2,
    "error": 3,
    "warning": 4,
    "notice": 5,
    "info": 6,
    "debug": 7,
}

# RFC5424 Facility codes (16 = local use 0)
FACILITY = {
    "kernel": 0,
    "user": 1,
    "mail": 2,
    "daemon": 3,
    "auth": 4,
    "syslog": 5,
    "lpr": 6,
    "news": 7,
    "uucp": 8,
    "cron": 9,
    "local0": 16,
    "local1": 17,
    "local2": 18,
    "local3": 19,
    "local4": 20,
    "local5": 21,
    "local6": 22,
    "local7": 23,
}


def calculate_priority(facility: str, severity: str) -> int:
    """Calculate PRI value for syslog"""
    fac = FACILITY.get(facility, 16)  # Default to local0
    sev = SEVERITY.get(severity, 6)  # Default to info
    return (fac * 8) + sev


def generate_event_id():
    """Generate a unique event ID"""
    return f"S-1-5-21-{random.randint(1000000000, 9999999999)}"


def generate_inode():
    """Generate a realistic inode number"""
    return str(random.randint(1000000, 9999999))


def send_syslog(
    message: str,
    hostname: str = "isilon-cluster",
    app_name: str = "OneFS",
    severity: str = "info",
    facility: str = "local0",
) -> bool:
    """Send a single RFC5424 syslog message via RFC5425 (TLS) or plain TCP/UDP"""
    try:
        pri = calculate_priority(facility, severity)
        timestamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        process_id = "-"
        msg_id = "-"
        structured_data = "-"

        # RFC5424 format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        syslog_msg = f"<{pri}>1 {timestamp} {hostname} {app_name} {process_id} {msg_id} {structured_data} {message}"

        if PROTOCOL.upper() == "UDP":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(syslog_msg.encode(), (SYSLOG_SERVER, SYSLOG_PORT))
            sock.close()
        else:  # TCP with optional TLS (RFC 5425)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # RFC 5425: TLS Transport of Syslog
            if USE_TLS:
                context = ssl.create_default_context()
                if not VERIFY_CERT:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=SYSLOG_SERVER)
            
            sock.connect((SYSLOG_SERVER, SYSLOG_PORT))
            sock.sendall(syslog_msg.encode())
            sock.close()

        print(f"✓ Sent: {message[:70]}...")
        return True
    except Exception as e:
        print(f"✗ Error sending syslog: {e}")
        return False


def send_audit_event(
    user_id: str,
    user_sid: str = None,
    zone_name: str = "ZONE_DEFAULT",
    zone_id: str = "1",
    client_ip: str = "192.168.1.100",
    protocol: str = "SMB",
    operation: str = "OPEN",
    nt_status: str = "SUCCESS",
    desired_access: int = 1048705,
    is_directory: str = "FILE",
    create_result: str = "OPENED",
    inode: str = None,
    filename: str = "/ifs/data/example.txt",
    cluster_name: str = "isilon-cluster",
    severity: str = "info",
) -> bool:
    """Send a PowerScale Isilon audit event in pipe-delimited format"""
    try:
        # Generate missing values
        if user_sid is None:
            user_sid = generate_event_id()
        if inode is None:
            inode = generate_inode()
                
        # Create pipe-delimited audit message matching PowerScale format
        audit_message = f"{user_sid}|{user_id}|{zone_name}|{zone_id}|{client_ip}|{protocol}|{operation}|{nt_status}|{desired_access}|{is_directory}|{create_result}|{inode}|{filename}"
        
        return send_syslog(
            audit_message,
            hostname=cluster_name,
            app_name="OneFS-Audit",
            severity=severity,
            facility="local0",
        )
    except Exception as e:
        print(f"✗ Error sending audit event: {e}")
        return False


def send_sample_audit_events():
    """Send a series of sample PowerScale Isilon HDFS audit events"""
    print(
        f"Sending PowerScale Isilon HDFS audit events to {SYSLOG_SERVER}:{SYSLOG_PORT} via {PROTOCOL}\n"
    )

    # Sample HDFS audit events with different operations
    sample_events = [
        # File creation
        {
            "user_id": "hadoop",
            "zone_name": "ZONE_HDFS",
            "client_ip": "192.168.1.100",
            "protocol": "HDFS",
            "operation": "CREATE",
            "nt_status": "SUCCESS",
            "desired_access": 123456,
            "is_directory": "FILE",
            "create_result": "CREATED",
            "filename": "/data/input/dataset_2025.txt",
            "severity": "info",
        },
        # File append
        {
            "user_id": "hadoop",
            "zone_name": "ZONE_HDFS",
            "client_ip": "192.168.1.100",
            "protocol": "HDFS",
            "operation": "APPEND",
            "nt_status": "SUCCESS",
            "desired_access": 123457,
            "is_directory": "FILE",
            "create_result": "APPENDED",
            "filename": "/data/input/dataset_2025.txt",
            "severity": "info",
        },
        # File open/read
        {
            "user_id": "mapreduce",
            "zone_name": "ZONE_HDFS",
            "client_ip": "192.168.1.105",
            "protocol": "HDFS",
            "operation": "OPEN",
            "nt_status": "SUCCESS",
            "desired_access": 1048576,
            "is_directory": "FILE",
            "create_result": "OPENED",
            "filename": "/data/input/dataset_2025.txt",
            "severity": "info",
        },
        # Directory creation
        {
            "user_id": "hadoop",
            "zone_name": "ZONE_HDFS",
            "client_ip": "192.168.1.100",
            "protocol": "HDFS",
            "operation": "MKDIR",
            "nt_status": "SUCCESS",
            "desired_access": 123458,
            "is_directory": "DIR",
            "create_result": "CREATED",
            "filename": "/data/output/results_2025",
            "severity": "notice",
        },
        # File close
        {
            "user_id": "hadoop",
            "zone_name": "ZONE_HDFS",
            "client_ip": "192.168.1.100",
            "protocol": "HDFS",
            "operation": "CLOSE",
            "nt_status": "SUCCESS",
            "desired_access": 123459,
            "is_directory": "FILE",
            "create_result": "CLOSED",
            "filename": "/data/input/dataset_2025.txt",
            "severity": "info",
        },
        # File rename
        {
            "user_id": "hadoop",
            "zone_name": "ZONE_HDFS",
            "client_ip": "192.168.1.100",
            "protocol": "HDFS",
            "operation": "RENAME",
            "nt_status": "SUCCESS",
            "desired_access": 123460,
            "is_directory": "FILE",
            "create_result": "RENAMED",
            "filename": "/data/input/dataset_2025_processed.txt",
            "severity": "notice",
        },
        # File delete
        {
            "user_id": "hadoop",
            "zone_name": "ZONE_HDFS",
            "client_ip": "192.168.1.100",
            "protocol": "HDFS",
            "operation": "DELETE",
            "nt_status": "SUCCESS",
            "desired_access": 123461,
            "is_directory": "FILE",
            "create_result": "DELETED",
            "filename": "/data/temp/old_cache.dat",
            "severity": "notice",
        },
        # Set permissions
        {
            "user_id": "hdfs",
            "zone_name": "ZONE_HDFS",
            "client_ip": "192.168.1.50",
            "protocol": "HDFS",
            "operation": "SETPERMISSION",
            "nt_status": "SUCCESS",
            "desired_access": 123462,
            "is_directory": "FILE",
            "create_result": "PERM_CHANGED",
            "filename": "/data/secure/sensitive_data.csv",
            "severity": "notice",
        },
        # Set owner
        {
            "user_id": "hdfs",
            "zone_name": "ZONE_HDFS",
            "client_ip": "192.168.1.50",
            "protocol": "HDFS",
            "operation": "SETOWNER",
            "nt_status": "SUCCESS",
            "desired_access": 123463,
            "is_directory": "FILE",
            "create_result": "OWNER_CHANGED",
            "filename": "/data/shared/report.txt",
            "severity": "notice",
        },
        # List status
        {
            "user_id": "analyst",
            "zone_name": "ZONE_HDFS",
            "client_ip": "192.168.1.110",
            "protocol": "HDFS",
            "operation": "LISTSTATUS",
            "nt_status": "SUCCESS",
            "desired_access": 1048576,
            "is_directory": "DIR",
            "create_result": "LISTED",
            "filename": "/data/input",
            "severity": "info",
        },
        # Get file status
        {
            "user_id": "analyst",
            "zone_name": "ZONE_HDFS",
            "client_ip": "192.168.1.110",
            "protocol": "HDFS",
            "operation": "GETFILESTATUS",
            "nt_status": "SUCCESS",
            "desired_access": 1048576,
            "is_directory": "FILE",
            "create_result": "RETRIEVED",
            "filename": "/data/output/results.parquet",
            "severity": "info",
        },
        # Access denied
        {
            "user_id": "guest",
            "zone_name": "ZONE_HDFS",
            "client_ip": "192.168.1.200",
            "protocol": "HDFS",
            "operation": "OPEN",
            "nt_status": "ACCESS_DENIED",
            "desired_access": 1048576,
            "is_directory": "FILE",
            "create_result": "DENIED",
            "filename": "/data/confidential/secret_keys.txt",
            "severity": "warning",
        },
        # Directory delete
        {
            "user_id": "hadoop",
            "zone_name": "ZONE_HDFS",
            "client_ip": "192.168.1.100",
            "protocol": "HDFS",
            "operation": "DELETE",
            "nt_status": "SUCCESS",
            "desired_access": 123461,
            "is_directory": "DIR",
            "create_result": "DELETED",
            "filename": "/data/temp",
            "severity": "notice",
        },
    ]

    for event in sample_events:
        send_audit_event(**event)
        time.sleep(0.3)

    print("\n✓ All sample HDFS audit events sent!")


if __name__ == "__main__":
    # Send sample audit events
    send_sample_audit_events()

    # Example: Send custom audit event
    # send_audit_event(
    #     user_id="testuser",
    #     client_ip="192.168.1.99",
    #     operation="OPEN",
    #     filename="/ifs/test/myfile.txt",
    #     severity="info",
    # )
