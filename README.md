# Interactive Security Policy Program (SecOps Pro)

SecOps Pro is a single-session Python CLI and Web application that guides users through the four phases of organizational security management:
1. Policy Development
2. Control Implementation
3. Compliance Audits
4. Incident Response

## Installation

This application relies entirely on standard Python libraries, with the exception of the optional web-based dashboard which requires Flask.

1. Ensure Python 3.8+ is installed.
2. Install the web dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### 1. Web Dashboard (Recommended)
To launch the beautiful, interactive dashboard built with Tailwind CSS:
```bash
python app.py
```
Then navigate to `http://127.0.0.1:5000` in your web browser.

### 2. Traditional CLI Interface
If you prefer a text-based console interface for managing your modules:
```bash
python main.py
```

## Running Tests

Automated unit tests ensure the core backend logic operates securely over the 4 module phases. To run the tests:
```bash
python test_security.py
```
