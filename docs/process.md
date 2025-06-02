# Process of the Application

## Components

### CaptureManager

The CaptureManager is responsible for managing packet capture on a network interface and distributing captured packets to a list of analyzers. It provides methods to start and stop packet capture, add analyzers to the list, and handle packet distribution to the analyzers.

### Analyzers

Analyzers are responsible for analyzing specific types of network packets. Each analyzer inherits from the abstract base class Analyzer and implements the analyzePacket method to handle packets of a specific protocol. The application includes several analyzers, such as:

- **ARPAnalyzer**: Analyzes ARP packets and updates the host manager.
- **DHCPAnalyzer**: Analyzes DHCP packets and updates the host manager.
- **mDNSAnalyzer**: Analyzes mDNS packets and updates the host manager.
- **STPAnalyzer**: Analyzes STP packets and updates the host manager.

### HostManager

The HostManager manages host information and updates the JSON representation of hosts. It maintains a database of hosts and updates their information based on captured packets.

## Process Flow

<ol> 
  <li><b>Initialization</b>:</li>

- The application starts by loading the vendor database using the loadVendorDatabase function.
- The network interface and timeout duration are retrieved from environment variables.
- The HostManager is created to manage host information.

<li><b>Packet Capture</b>:</li>

- The CaptureManager is created and initialized with the network interface.
Various analyzers (e.g., DHCPAnalyzer, mDNSAnalyzer, ARPAnalyzer, STPAnalyzer) are created and added to the CaptureManager.

<li><b>Starting Capture</b>:</li>

- The CaptureManager starts capturing packets on the specified network interface.
Captured packets are distributed to the analyzers for processing.

<li><b>Packet Analysis</b>:</li>

- Each analyzer processes the packets it receives. For example, the mDNSAnalyzer extracts DNS queries and responses from mDNS packets and updates the host manager with the extracted information.

<li><b>Host Management</b>:</li>

- The HostManager updates the host database with information extracted from the analyzed packets. This includes updating MAC addresses, hostnames, IP addresses, and other relevant details.

<li><b>Signal Handling</b>:</li>

- When a specific signal is received, the HostManager dumps the current host information to a JSON file.
</ol>

## Class Diagram

If we take LLDP as an example, we have the following class diagram:

<img src="uml_diagram_LLDP.png" alt="LLDPAnalyzer Class Diagram" width="500"/>

[]: # (END) docs/process.md

[]: # (BEGIN) docs/uml_diagram_LLDP.png
