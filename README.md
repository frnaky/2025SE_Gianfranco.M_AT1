# LogVault

## Introduction

Welcome to LogVault, a secure and safe software solution designed to help development teams record their code, track progress and streamline workflow.

![Screencap of dashboard](/static/images/cap1.png?raw=true)

## Features

- ### Secure Session Management via Flask-Login
  - Storing session data in a **secure cookie**, with session persistence for user convenience.
  - Reauthentication occurs every hour, and after closing the browser instance.
- ### Password Resetting via SMTP + Flask-Mail
- ### Control of Account + Data Privacy
  - Deleting Account
  - Downloading user data from database
- ### Secure Development
  - Password and baming requirements via RegEx
  - BCrypt used to hash and salt passwords
  - Time-Stamped diary entries
  - External JavaScript
  - Input Sanitisation
- ### Security Logs
- ### WC3 PWA Standards
  - HTTPS supported
  - manifest.json included
  - Responsive - Tested on mobile devices

## Installation

1. Clone Repository within a bash terminal.\
   `git clone https://github.com/frnaky/2025SE_Gianfranco.M_AT1`

2. CD into directory.\
   `cd 2025SE_Gianfranco.M_AT1`

3. Setup venv. (Install if needed)\
   `virtualenv venv`

4. Activate venv.\
   `source venv/Scripts/activate`

5. Install prerequisites.\
   `pip install -r requirements.txt`

6. Run the application through a terminal.\
   `python main.py`

7. Open webpage locally.\
   `https://127.0.0.1:5000`

## Usage

1. Register for a new account or log in with your existing credentials.
2. Create a new diary entry by clicking on the "Create Log" button.
3. Fill in the details of your entry and save it.
4. View, edit, or delete your entries from the dashboard.
5. Use the search bar to find specific entries.

## Working Login

- **Username:** `Franky` (Not needed for Sign-In)
- **Email:** `gmanieli5647@gmail.com`
- **Password:** `Software1sTheBest!`
- **Team Name:** `TempeHS`
- **Team Password:** `Software1sTheBest!`

## Common Issues

**HTTP ERROR 502**

1.  Within codespaces, go to the ports tab within the terminal panel.
2.  Right-click on the 5000 Port row.
3.  Change port protocol to HTTPS

**App not launching due to issues with imported libraries**

1. Uninstall requirements\
   `pip uninstall -r requirements.txt`
2. Clear cache\
   `python -m pip cache purge`
3. Reinstall requirements\
   `pip install -r requirements.txt`

## License

This project is licensed under the GNU General Public License. See the [LICENSE](LICENSE) file for more details.

## Contact

For any questions or feedback, please contact Gianfranco at gmanieli5647@gmail.com
