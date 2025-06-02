# Main Page

## NetProbe

**NetProbe** is a network mapping application designed to passively capture and analyze network traffic. The application utilizes various protocol analyzers to gather information about devices and their interactions on the network.

### Features

- **Packet Capture**: Captures network packets using the PcapPlusPlus library.
- **Protocol Analysis**: Supports analysis for multiple protocols including ARP, DHCP, STP, and more.
- **Host Management**: Maintains a database of hosts and updates their information based on captured packets.
- **Signal Handling**: Dumps host information to a file upon receiving specific signals.

### Components

- **CaptureManager**: Manages packet capture and distribution to analyzers.
- **Analyzers**: Abstract base class for analyzing network packets. Derived classes implement specific protocol analysis.
- **HostManager**: Manages host information and updates the JSON representation of hosts.

### Getting Started

1. **Build the Project from source**:
  ```sh
  mkdir build
  cd build
  cmake ..
  make
  ```

2. **Run the Application using docker-compose**:
  ```sh
  docker-compose up
  ```

### Documentation

- **[Process of the Application](docs/process.md)**: Overview of the application components and process flow.

- **[Adding a New Analyzer](docs/analyzers.md)**: Instructions for adding a new analyzer to the application.

For more information, visit the [GitHub repository](https://github.com/an0n1mity/cartographie-passive).
