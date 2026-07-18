# A R G U S

ARGUS is a simple Flask-based file integrity monitoring dashboard. It lets administrators monitor folders, verify file hashes, detect known malware hashes and review logs.

## Features

- Web-based login-protected dashboard
- Start/stop directory monitoring
- Generate baseline file hashes for monitored folders
- Run integrity checks against saved hashes
- Detect deleted, changed, and newly created files
- Compare files against known malware hashes
- Periodic automatic scanning with configurable interval
- Logs and issue tracking with acknowledge support

## Requirements

- Python 3.8+
- Flask

## Installation

1. Clone the repository.
2. Create and activate a Python virtual environment:

```bash
python -m venv venv
venv\Scripts\activate
```

3. Install dependencies:

```bash
pip install flask
```

## Configuration

Optional environment variables:

- `SECRET_KEY` — Flask session secret key (default: `devsecretkey`)
- `SECUREDB_PASSWORD` — login password for the web app (default: `admin`)

Example (PowerShell):

```powershell
$env:SECRET_KEY = "mysecret"
$env:SECUREDB_PASSWORD = "admin123"
```

## Running the App

Start the application:

```bash
python app.py
```

Then open your browser at:

```
http://127.0.0.1:5000/
```

## Usage

1. Login using the configured password.
2. On the dashboard, enter a folder path and click `Monitor` to begin monitoring that directory.
3. Use `Integrity check` to verify current file hashes against the saved baseline.
4. Start or stop periodic scanning using the scan controls.
5. View `Logs` for historical activity and unresolved issues.
6. Acknowledge issues from the logs page once they have been reviewed.

## Project Structure

- `app.py` — main Flask application and monitoring logic
- `templates/` — HTML templates for the UI
- `logs/` — stores `logs.json` and `issues.json`
- `malwares/` — contains `malware hashes.txt` used for known malware detection
- `hashes/` — generated at runtime when directories are monitored

## Notes

- This project uses MD5 hashes for file integrity verification.
