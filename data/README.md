# CyberVision AI - Sample Dataset Documentation

## Overview
This directory contains `sample_cybersecurity.csv`, a synthetic dataset specifically engineered for demonstration, testing, and validation of the CyberVision AI analytics platform.

> **IMPORTANT DISCLAIMER**:  
> All records in this dataset are **100% synthetically generated** for educational and demonstration purposes. They represent simulated network telemetry and do **NOT** depict live attacks against real-world production systems or actual individuals.

---

## Schema & Column Reference

| Column Name | Data Type | Description | Example |
| :--- | :--- | :--- | :--- |
| `timestamp` | Datetime (ISO format) | Log timestamp for event ordering and time-series trends | `2026-10-24 08:04:10` |
| `source_ip` | String (IPv4) | Source IP address originating the connection | `45.33.32.156` |
| `destination_ip` | String (IPv4) | Target/destination IP address receiving packets | `192.168.1.10` |
| `source_port` | Integer | Originating network ephemeral port | `54321` |
| `destination_port` | Integer | Destination service port (e.g., 80, 443, 22, 53) | `80` |
| `protocol` | String | Transport protocol (`TCP`, `UDP`, `ICMP`) | `TCP` |
| `bytes_transferred` | Integer | Total data volume transferred in bytes | `425100` |
| `packets` | Integer | Total number of packets transmitted | `320` |
| `attack_type` | String | Threat classification label (e.g., `Benign`, `DoS Hulk`, `DDoS`, `PortScan`, `SSH Brute Force`, `Botnet C2`, `SQL Injection`) | `DoS Hulk` |
| `severity` | String | Normalized threat severity (`Critical`, `High`, `Medium`, `Low`, `Informational`) | `High` |
| `event_type` | String | Descriptive operational category of the security event | `HTTP Flood` |
| `login_attempts` | Integer | Total recorded authentication attempts in the session | `0` |
| `failed_login_attempts` | Integer | Total rejected authentication attempts | `0` |

---

## Represented Scenarios
1. **Benign Baseline Traffic**: Normal HTTPS (443) web browsing, DNS queries (port 53), cloud sync operations, and code repository interactions.
2. **Denial of Service (DoS Hulk & DDoS)**: High-rate traffic spikes targeting HTTP (80) and UDP reflection flows with large byte transfers.
3. **Reconnaissance (PortScan)**: Sequential single-packet probes originating from suspicious hosts across multiple destination ports (21, 22, 23, 80, 443, 3389).
4. **Credential Brute-Force**: Repeated failed login attempts on SSH (port 22) within short intervals.
5. **Web Application Exploitation**: Targeted SQL Injection probes against web endpoints.
6. **Botnet C2**: Periodic command-and-control beaconing packets over port 8080.
