# FackNTA - JEE Results Monitor & Tracker

A comprehensive monitoring and tracking system for JEE (Joint Entrance Examination) Main 2026 results. This project consists of two main components that work together to monitor the NTA score-card page and track result updates.


## Table of Contents

- [Motivation](#motivation)
- [Features](#features)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Installation](#installation)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Contact](#contact)

## Motivation

**The Problem**: When JEE Main results are released by the NTA, their official website crashes within 15 minutes due to massive traffic from hundreds of thousands of students trying to access their scores simultaneously. This means you have only a narrow window to check your results before the server becomes inaccessible.

**The Solution**: This project automatically monitors the NTA website 24/7 and alerts you the **instant** results go live—often within minutes of official release. You won't miss your window!

### How It Works

The monitoring scripts run continuously in the background and check the NTA website at regular intervals (default: every 30 seconds). When results are detected to be live, your computer will **play an audio alarm** — a recording saying **"RESULTS ARE OUT"** to immediately notify you.

**Set it and forget it**: Start the monitor before the expected result date, let it run in the background, and you'll get an instant alert the moment results are available. By the time you hear the alarm and open the website, you'll be among the first to access the results page before it crashes.

## Features

### JEE Results Monitor (`jee_results_monitor.py`)
- **Structural Fingerprinting**: Monitors the NTA score-card login page for structural changes that indicate results are live
- **Multi-Layer Detection**: 
  - HTML skeleton hashing
  - Form action URL monitoring
  - JavaScript & CSS asset tracking
  - New link detection (e.g., "Download Score Card")
  - Page title changes
  - POST probe testing for redirect changes
- **Anti-False-Alarm System**:
  - Confidence scoring (0-100)
  - Multi-layer validation
  - 3-check persistence verification
  - 5-minute cooldown between alerts
- **Sound Notifications**: Plays `alarm.mp3` (a recording saying **"RESULTS ARE OUT"**) when results are detected—you'll hear it instantly even from another room!
- **Customizable Intervals**: Adjustable monitoring frequency

### Main Tracker (`Main_tracker.py`)
- **Web Scraping**: Fetches the latest JEE results page
- **Timestamp Tracking**: Monitors "Last Updated" timestamps
- **State Management**: Maintains state across sessions
- **Alarm System**: Visual and audio notifications
- **GUI Interface**: Tkinter-based user interface
- **Multi-threading**: Non-blocking operations

## Project Structure

```
fackNTA/
├── jee_results_monitor.py      # JEE results structural monitor
├── Main_tracker.py             # Main tracker with GUI
├── requirements.txt            # Python dependencies
├── START.sh                    # Linux/Mac startup script
├── START.bat                   # Windows startup script
└── README                      # This file
```

## Requirements

- **Python**: 3.8 or higher
- **Operating System**: Windows, macOS, or Linux
- **Internet Connection**: Required for monitoring NTA website
- **Dependencies**: Listed in `requirements.txt`

### Dependencies

- `beautifulsoup4` - HTML parsing
- `requests` - HTTP requests
- `pygame` - Audio alerts
- `tkinter` - GUI (usually included with Python)
- `lxml` - XML/HTML parsing

## Installation

### Step 1: Clone/Download the Project


If you have Git installed, clone the repository to your desired location:

```bash
git clone https://github.com/DikshitRJ/fackNTA.git
cd fackNTA
```

### Step 2: Setup Python Virtual Environment

Run the following command to create a virtual environment, activate it, and install dependencies:

**Windows:**
```bash
python -m venv .venv && .venv\Scripts\activate && pip install -r requirements.txt
```

**Linux/macOS:**
```bash
python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
```

### Step 3: Verify Installation

Verify that all packages are installed correctly:

```bash
pip list
```

You should see all packages from `requirements.txt` listed.

## Getting Started

### Quick Start

#### Windows:
Double-click `START.bat` to launch both monitoring scripts.

#### Linux/macOS:
```bash
bash START.sh
```

Or manually:

**Windows:**
```bash
.venv\Scripts\python.exe jee_results_monitor.py
.venv\Scripts\python.exe Main_tracker.py
```

**Linux/macOS:**
```bash
./.venv/bin/python jee_results_monitor.py
./.venv/bin/python Main_tracker.py
```

## Usage

### JEE Results Monitor

The monitor supports several command-line options:

```bash
# Default: 300-second check interval
python jee_results_monitor.py

# Custom interval (check every 15 seconds)
python jee_results_monitor.py --interval 15

# Silent mode (no sound alerts)
python jee_results_monitor.py --no-sound

# One-shot stability test
python jee_results_monitor.py --test
```

### Main Tracker

Simply run the script to start the GUI-based tracker:

```bash
python Main_tracker.py
```

The tracker will:
- Fetch the latest JEE results page
- Monitor for timestamp updates
- Display notifications when changes are detected
- Maintain a state file (`state.json`) with last update information

## Configuration

### Monitor Settings

The JEE Results Monitor uses these detection thresholds:

- **Cumulative Confidence Threshold**: ≥ 60%
- **Minimum Triggers**: ≥ 2 detection layers
- **Check Persistence**: 3 consecutive checks (10s apart)
- **Alert Cooldown**: 5 minutes between alert bursts
- **Default Check Interval**: 30 seconds

### Customizing the Alarm Sound

The monitor plays `alarm.mp3` when results are detected. You can replace this file with your own audio file:


1. Prepare your audio file in **MP3 format**
   - Keep the filename as `alarm.mp3`
   - Recommended duration: 5-10 seconds
   - Use a clear, loud sound that will wake you up

2. Place your `alarm.mp3` file in the project root directory (same level as the scripts)

3. The next time you run the monitor, it will play your custom alarm

4. If you wish to exit, press CTRL + C, the program will give you a summary of all requests made until that point.


#### Tips for Creating an Alarm Audio File

- **Use Online Tools**: Convert text-to-speech or music files to MP3 using free online converters
- **Record Your Own**: Use your phone or computer's built-in recorder to record a custom message
- **System Sounds**: Extract alarm sounds from your operating system
- **Music/Alert Services**: Download royalty-free alarm sounds from sites like Zapsplat or Freesound


## Troubleshooting

### Virtual Environment Issues

**Problem**: `Virtual environment not found` error

**Solution**: Create the virtual environment first:

```bash
# Windows
python -m venv .venv

# Linux/macOS
python3 -m venv .venv
```

### Module Not Found Errors

**Problem**: `ModuleNotFoundError: No module named 'urllib3'` or similar

**Solution**: Ensure the virtual environment is activated and dependencies are installed:

```bash
# Windows
.venv\Scripts\activate
pip install -r requirements.txt

# Linux/macOS
source .venv/bin/activate
pip install -r requirements.txt
```

### Network Errors

**Problem**: Connection timeouts or timeouts when trying to reach NTA website

**Solution**:
- Check your internet connection
- Ensure the NTA website is accessible
- Try increasing the timeout or check interval
- Some ISPs/networks may block the connection; consider using a VPN

### No Sound Alerts

**Problem**: Audio alerts not working

**Solution**:
- Ensure pygame is properly installed: `pip install --upgrade pygame`
- Check your system volume settings
- Try running with sound explicitly enabled (default)
- Use `--no-sound` flag if you prefer silent operation

### GUI Not Displaying (tkinter)

**Problem**: `_tkinter.TclError` or GUI window not appearing

**Solution**:
- Linux/macOS users may need to install tkinter system package:
  ```bash
  # Ubuntu/Debian
  sudo apt-get install python3-tk
  
  # macOS (with Homebrew)
  brew install python-tk
  ```

## Notes

- **Always Running**: Keep the monitor running 24/7 before and during the expected result release date. The earlier you start it, the more reliable the detection.
- **Alarm File**: The `alarm.mp3` file contains a voice recording saying **"RESULTS ARE OUT"**. Make sure it exists in the project directory for notifications to work. You can replace it with your own audio file if desired (must be in MP3 format).
- **Instant Alert**: Once results go live on the NTA website, the alarm will typically sound within 1-3 minutes of the official release, giving you ample time before the website crashes.
- **No Manual Checking**: You don't need to manually refresh the NTA website—the monitor does it automatically every 30 seconds (or your custom interval).
- **Minimize False Positives**: The multi-layer detection system is designed to only alert when it's very confident results are actually live, reducing unnecessary alarms.
- **Stop Command**: Use Ctrl+C in the terminal to stop the monitor at any time.
- **Results Data**: All check events are timestamped and can be reviewed in the log file for reference.
- **Rate Limiting**: The system respects rate limiting with configurable check intervals.
- **Security**: The project includes proper SSL certificate verification for secure HTTPS connections.

## Important Reminders

1. **Start Early**: Begin monitoring at least a day before the expected results release. NTA announcements sometimes come earlier than expected.
2. **Keep Your Device On**: Your computer must remain powered on and connected to the internet for the monitor to work.
3. **Volume Up**: Ensure your speakers/headphones are connected and volume is audible so you hear the alarm.
4. **Quick Action**: When the alarm sounds, immediately open the NTA website to check your results before the rush crashes the server.


## Contact

If you run into any issues with the program not working on your computer even after setup, please contact either white.9igga OR .sciron on DISCORD only.
Please do not contact us for guide on installation, the README has all commands mentioned in it. PLease Contact only if you receive any error while and/or after running the program.


THANK YOU AND ALL THE BEST FOR RESULTS!

Cheers,
white.9igga and .sciron




