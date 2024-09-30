

# Intrusion Detection System (IDS)

This is a simple Intrusion Detection System (IDS) built with Python that captures network packets using Scapy and monitors active network services. The IDS provides a graphical user interface (GUI) built with Tkinter, allowing users to start and stop packet sniffing, view active network services, and save captured data to a file.

## Features

- **Packet Capture**: Captures and displays network packets in real-time, including source and destination IP addresses and the protocol used.
- **Active Service Monitoring**: Lists currently active network services and their status using `psutil`.
- **Real-Time Monitoring**: Provides the ability to start and stop packet monitoring through a user-friendly GUI.
- **Data Persistence**: Save the captured network data to a file for further analysis.
- **GUI**: Easy-to-use interface to start and stop monitoring, display active services, and save data.

## Screenshots

_TODO: Add screenshots of the application._

## Requirements

- **Python 3.6+**
- **Libraries**:
  - `tkinter` (for GUI)
  - `scapy` (for packet sniffing)
  - `psutil` (for system and service monitoring)
  
You can install the required libraries by running:

```bash
pip install -r requirements.txt
```

### Optional:

You can set the network interface to monitor using an environment variable:

```bash
export NETWORK_INTERFACE=eth0
```

If not set, the default interface (`eth0`) will be used.

## Installation and Usage

1. Clone this repository:

```bash
git clone https://github.com/your-username/intrusion-detection-system.git
cd intrusion-detection-system
```

2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

3. Run the application:

```bash
python main.py
```

## How It Works

- **Packet Capture**: 
  The application uses Scapy to sniff network packets on the specified interface (`eth0` by default). Only IP packets are captured, and their source, destination, and protocol are displayed in the GUI.
  
- **Monitoring Services**: 
  `psutil` is used to list active network connections and services running on the system. This data can be displayed in the GUI when requested.

- **Saving Captured Data**: 
  Users can save captured network packets to a file using the "Save Output to File" button.

## GUI Overview

- **Start Monitoring**: Begins capturing network packets.
- **Stop Monitoring**: Stops packet capture.
- **Show Active Services**: Displays currently active network services.
- **Save Output to File**: Saves captured data to a text file.
- **Quit**: Closes the application.

