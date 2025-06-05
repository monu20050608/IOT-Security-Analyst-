# IOT-Security-Analyst-
iot-security-analyzer The The IoT Security Analyzer is a tool designed to assess and enhance the security of Internet of Things (IoT) devices. The RPL Attack Detection System is designed to simulate and analyze security threats in IoT networks using the RPL protocol in Contiki-NG. 
 
# RPL-Based Attack Detection in Contiki-NG Using IDS
# Overview
This project simulates a secure IoT network in the Contiki-NG operating system using Cooja. It demonstrates how an Intrusion Detection System (IDS) can detect various RPL-based routing and application-layer attacks in a 6LoWPAN network. The IDS logic is embedded in a central UDP server node (rplserver) that monitors network traffic from multiple client nodes.
# Objective
To implement and evaluate a lightweight, rule-based IDS capable of detecting:

Blackhole attacks (dropping packets)
Flooding attacks (sending excessive packets)
Replay attacks (sending old packets)
Normal behavior (for comparison)
# Simulation Setup
Network Type: RPL-based 6LoWPAN
Simulation Tool: Cooja (part of Contiki-NG)
Node Roles:
rplclient.c – Normal UDP client
rplblackhole.c – Drops all packets (Blackhole Attacker)
rplflood.c – Sends packets at high frequency (Flooding Attacker)
rplreplay.c – Repeats old packets (Replay Attacker)
rplserver.c – IDS-enabled UDP Server (detection logic)
# How It Works
All clients send UDP packets to the rplserver node.
The server inspects traffic patterns such as:
Packet frequency
Repeated content
Missing packets
Based on thresholds and behavior, the IDS detects anomalies and classifies nodes as malicious or normal.
# Key Features
Simulates three distinct RPL-based attacks.
Lightweight IDS suitable for constrained IoT nodes.
Real-time detection via server console outputs.
Helps analyze behavioral patterns for each type of attack.
# Use Cases
IoT security research
Academic demonstration of RPL attacks and defenses
Testing IDS strategies for low-power networks
# Requirements
Contiki-NG (with Cooja simulator)
Java (for running Cooja)
Basic knowledge of C programming and network protocols (RPL, UDP)
