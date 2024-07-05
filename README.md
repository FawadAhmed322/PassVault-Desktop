# Passvault-Desktop

Passvault-Desktop is a secure and user-friendly desktop application for managing your passwords. Built with PySide6 and Flask, it offers robust features such as user authentication, secure storage, and easy retrieval of credentials. Ideal for personal and professional use, Passvault-Desktop ensures that your sensitive information remains safe and accessible.

## Features

- User registration and login
- Secure session management
- Password encryption and decryption
- Add, update, delete, and retrieve credentials
- CSV import and export for credentials

## Installation

### Prerequisites

- Python 3.7+
- Flask
- PySide6
- Other dependencies listed in `requirements.txt`

### Steps

1. Clone the repository:

    ```sh
    git clone https://github.com/YOUR_USERNAME/Passvault-Desktop.git
    cd Passvault-Desktop
    ```

2. Create a virtual environment and activate it:

    ```sh
    python -m venv venv
    source venv/bin/activate   # On Windows use `venv\Scripts\activate`
    ```

3. Install the dependencies:

    ```sh
    pip install -r requirements.txt
    ```

4. Create a `.env` file in the root directory and add the following environment variables:

    ```env
    BASE_URL=http://localhost:5000
    SESSION_FILE=session_cookies.pkl
    SALT_FILE=salt.txt
    PASSWORD_FILE=password.txt
    DERIVED_KEY_FILE=derived_key.bin
    ```

5. Run the application:

    ```sh
    python app.py
    ```

## Usage

Explain how to use your application here.

## Contributing

Explain how to contribute to the project here.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
