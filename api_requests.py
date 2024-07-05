import os
from dotenv import load_dotenv
import base64
import pickle
import logging
import requests
import csv
from utils.crypto_utils import derive_key, encrypt, decrypt

# Load environment variables from .env file
load_dotenv()

# Retrieve configuration from environment variables
BASE_URL = os.getenv('BASE_URL')
SESSION_FILE = os.getenv('SESSION_FILE', 'session_cookies.pkl')
SALT_FILE = os.getenv('SALT_FILE', 'salt.txt')
PASSWORD_FILE = os.getenv('PASSWORD_FILE', 'password.txt')
DERIVED_KEY_FILE = os.getenv('DERIVED_KEY_FILE', 'derived_key.bin')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create a session object
session = requests.Session()

def save_session(session, filename=SESSION_FILE):
    """
    Save session cookies to a file.
    
    Args:
        session (requests.Session): The session object containing cookies.
        filename (str): The filename where session cookies will be saved.
    """
    try:
        with open(filename, 'wb') as f:
            pickle.dump(session.cookies, f)
        logger.info("Session saved to file.")
    except Exception as e:
        logger.error(f"Error saving session to file: {e}")
        raise

def load_session(session, filename=SESSION_FILE):
    """
    Load session cookies from a file.
    
    Args:
        session (requests.Session): The session object to update with loaded cookies.
        filename (str): The filename from which session cookies will be loaded.
    """
    try:
        with open(filename, 'rb') as f:
            session.cookies.update(pickle.load(f))
        logger.info("Session loaded from file.")
    except FileNotFoundError:
        logger.info("No saved session found. Please log in.")
    except Exception as e:
        logger.error(f"Error loading session from file: {e}")
        raise

def save_derived_key(key, filename=DERIVED_KEY_FILE):
    """
    Save the derived key to a file.

    Args:
        key (bytes): The derived key to save.
        filename (str): The filename where the derived key will be saved.
    """
    try:
        with open(filename, 'wb') as f:
            f.write(key)
        logger.info("Derived key saved to file.")
    except Exception as e:
        logger.error(f"Error saving derived key to file: {e}")
        raise

def load_derived_key(filename=DERIVED_KEY_FILE):
    """
    Load the derived key from a file.

    Args:
        filename (str): The filename from which the derived key will be loaded.

    Returns:
        bytes: The loaded derived key.

    Raises:
        FileNotFoundError: If the derived key file is not found.
        Exception: For any other errors during loading.
    """
    try:
        with open(filename, 'rb') as f:
            key = f.read()
        logger.info("Derived key loaded from file.")
        return key
    except FileNotFoundError:
        logger.error("Derived key file not found.")
        raise
    except Exception as e:
        logger.error(f"Error loading derived key from file: {e}")
        raise

def login(email, password, session=session):
    """
    Attempt to log in to the server with the provided email and password.
    
    Args:
        email (str): The user's email address.
        password (str): The user's password.
        session (requests.Session, optional): A requests session object. Defaults to a new session.
    
    Returns:
        dict: The JSON response from the server if the login is successful.
    
    Raises:
        requests.RequestException: If there is an error during the login request.
    """
    try:
        url = f"{BASE_URL}/api/login"
        data = {"email": email, "password": password}
        logger.info(f"Attempting to log in user {email} at {url}")
        
        response = session.post(url, json=data)
        response.raise_for_status()
        
        response_data = response.json()
        
        # Check for expected response data
        if not response_data:
            logger.error("Empty response received from server.")
            raise requests.RequestException("Empty response received from server.")
        
        # Get salt from the server response
        salt = response_data.get('salt')
        if not salt:
            logger.warning("No salt received from server.")
            raise requests.RequestException("No salt received from server.")
        
        # Derive the key using the password and salt
        derived_key = derive_key(password, base64.b64decode(salt))
        
        # Save session and derived key
        save_session(session)
        save_derived_key(derived_key)
        
        logger.info("Derived key created and saved successfully.")
        
        return response_data

    except requests.HTTPError as http_err:
        logger.error(f"HTTP error occurred during login: {http_err}")
        raise
    except requests.ConnectionError as conn_err:
        logger.error(f"Connection error occurred during login: {conn_err}")
        raise
    except requests.Timeout as timeout_err:
        logger.error(f"Timeout error occurred during login: {timeout_err}")
        raise
    except requests.RequestException as req_err:
        logger.error(f"Error during login: {req_err}")
        raise

def register(email, password, session=session):
    """
    Attempt to register a new user with the provided email and password.
    
    Args:
        email (str): The user's email address.
        password (str): The user's password.
        session (requests.Session, optional): A requests session object. Defaults to a new session.
    
    Returns:
        dict: The JSON response from the server if the registration is successful.
    
    Raises:
        requests.RequestException: If there is an error during the registration request.
    """
    try:
        url = f"{BASE_URL}/api/register"
        data = {"email": email, "password": password}
        logger.info(f"Attempting to register user {email} at {url}")
        
        response = session.post(url, json=data)
        response.raise_for_status()
        
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Error during registration: {e}")
        raise

def logout(session=session):
    """
    Log out the user by clearing the session cookies and notifying the server.

    Args:
        session (requests.Session): A requests session object.

    Returns:
        dict: The JSON response from the server if the logout is successful.

    Raises:
        requests.RequestException: If there is an error during the logout request.
    """
    try:
        # Define the URL for the API endpoint
        url = f"{BASE_URL}/api/logout"
        
        # Send a POST request to the server to log out
        response = session.post(url)
        response.raise_for_status()
        
        # Clear the session cookies
        session.cookies.clear()
        
        # Return the server response
        return response.json()
    
    except requests.RequestException as e:
        # Log and raise an error if there is a request-related issue
        logger.error(f"Error during logout: {e}")
        raise

def get_credentials(session=session):
    """
    Retrieve and decrypt stored credentials from the server.

    Args:
        session (requests.Session): A requests session object.

    Returns:
        dict: A dictionary containing the success status and decrypted credentials.

    Raises:
        requests.RequestException: If there is an error during the request.
        ValueError: If the derived key is not found.
        Exception: For any other errors during decryption.
    """
    try:
        # Define the URL for the API endpoint
        url = f"{BASE_URL}/api/get-credentials"
        
        # Send a GET request to the server to retrieve the credentials
        response = session.get(url)
        response.raise_for_status()
        
        # Extract the credentials from the response JSON
        credentials = response.json().get('credentials', [])

        # Load the stored derived key
        key = load_derived_key()
        if not key:
            raise ValueError("Derived key not found")

        decrypted_credentials = []
        for cred in credentials:
            # Decrypt the password using the stored derived key
            decrypted_password = decrypt(cred['password'], key)
            
            # Append the decrypted credentials to the list
            decrypted_credentials.append({
                'name': cred['name'],
                'url': cred['url'],
                'username': cred['username'],
                'password': decrypted_password
            })
        
        # Return the success status and decrypted credentials
        return {'success': True, 'credentials': decrypted_credentials, 'status': 200}
    
    except requests.RequestException as e:
        # Log and raise an error if there is a request-related issue
        logger.error(f"Error getting credentials: {e}")
        raise
    
    except ValueError as e:
        # Log and raise an error if the derived key is not found
        logger.error(f"Error with derived key: {e}")
        raise
    
    except Exception as e:
        # Log and raise any other errors that occur during decryption
        logger.error(f"Error decrypting credentials: {e}")
        raise

def add_credentials(credentials, session=session):
    """
    Add a batch of new credentials to the server.

    Args:
        credentials (list of dict): A list of credentials, where each credential is a dictionary with keys 'name', 'url', 'username', and 'password'.
        session (requests.Session): A requests session object.

    Returns:
        dict: The JSON response from the server if the addition is successful.

    Raises:
        requests.RequestException: If there is an error during the request.
        ValueError: If the derived key is not found or no valid credentials are provided.
        Exception: For any other errors during encryption.
    """
    try:
        # Load the stored derived key
        key = load_derived_key()
        if not key:
            raise ValueError("Derived key not found")

        valid_credentials = []

        # Validate and encrypt the passwords in the batch of credentials
        for credential in credentials:
            name = credential.get('name')
            username = credential.get('username')
            password = credential.get('password')

            if not name or not username or not password:
                logger.error(f"Missing mandatory fields in credential: {credential}")
                continue

            credential['password'] = encrypt(password, key)
            valid_credentials.append(credential)

        if not valid_credentials:
            raise ValueError("No valid credentials to add. Each credential must include 'name', 'username', and 'password'.")

        # Define the URL for the API endpoint
        url = f"{BASE_URL}/api/add-credentials"
        
        # Prepare the data payload
        data = {"credentials": valid_credentials}
        
        # Send a POST request to add the batch of credentials
        response = session.post(url, json=data)
        response.raise_for_status()
        
        # Parse the response
        result = response.json()

        # Handle partial success
        if result.get("status") == 207:
            logger.warning("Partial success adding credentials")
            if "errors" in result:
                for error in result["errors"]:
                    logger.error(f"Failed to add credential: {error['credential']} due to {error['error']}")
            return result
        
        # Log any errors if the server indicates some credentials failed to add
        if result.get("status") != 201:
            logger.error(f"Errors adding some credentials: {result.get('errors')}")
        
        return result
    
    except requests.RequestException as e:
        # Log and raise an error if there is a request-related issue
        logger.error(f"Error adding credentials batch: {e}")
        raise
    
    except ValueError as e:
        # Log and raise an error if the derived key is not found or no valid credentials are provided
        logger.error(f"Value error: {e}")
        raise
    
    except Exception as e:
        # Log and raise any other errors that occur during encryption
        logger.error(f"Error encrypting credentials: {e}")
        raise

def delete_credentials(credentials, session=session):
    """
    Delete a batch of credentials from the server.

    Args:
        credentials (list of dict): A list of credentials to be deleted, where each credential is a dictionary with keys 'name', 'username', and optionally 'url' and 'password'.
        session (requests.Session): A requests session object.

    Returns:
        dict: The JSON response from the server if the deletion is successful.

    Raises:
        requests.RequestException: If there is an error during the request.
        ValueError: If no valid credentials are provided.
        Exception: For any other errors during the process.
    """
    try:
        valid_credentials = []

        # Validate the credentials in the batch
        for credential in credentials:
            name = credential.get('name')
            username = credential.get('username')

            if not name or not username:
                logger.error(f"Missing mandatory fields in credential: {credential}")
                continue

            valid_credentials.append({'name': name, 'username': username})

        if not valid_credentials:
            raise ValueError("No valid credentials to delete. Each credential must include 'name' and 'username'.")

        # Define the URL for the API endpoint
        url = f"{BASE_URL}/api/delete-credentials"
        
        # Prepare the data payload
        data = {"credentials": valid_credentials}
        
        # Send a DELETE request to delete the batch of credentials
        response = session.delete(url, json=data)
        response.raise_for_status()
        
        # Return the server response
        return response.json()
    
    except requests.RequestException as e:
        # Log and raise an error if there is a request-related issue
        logger.error(f"Error deleting credentials batch: {e}")
        raise
    except ValueError as e:
        # Log and raise an error if no valid credentials are provided
        logger.error(f"Value error: {e}")
        raise
    except Exception as e:
        # Log and raise any other errors that occur during the process
        logger.error(f"Error processing credentials: {e}")
        raise

def update_credentials(credentials, session=session):
    """
    Update a batch of credentials on the server.

    Args:
        credentials (list of dict): A list of credentials, where each credential is a dictionary with keys 'oldName', 'oldUsername', 'newName', 'newUrl', 'newUsername', and 'newPassword'.
        session (requests.Session): A requests session object.

    Returns:
        dict: The JSON response from the server if the update is successful.

    Raises:
        requests.RequestException: If there is an error during the request.
        ValueError: If the derived key is not found or no valid credentials are provided.
        Exception: For any other errors during encryption.
    """
    try:
        # Load the stored derived key
        key = load_derived_key()
        if not key:
            raise ValueError("Derived key not found")

        valid_credentials = []

        # Validate and encrypt the passwords in the batch of credentials
        for credential in credentials:
            old_name = credential.get('oldName')
            old_username = credential.get('oldUsername')
            new_name = credential.get('newName')
            new_url = credential.get('newUrl', '')
            new_username = credential.get('newUsername')
            new_password = credential.get('newPassword')

            if not old_name or not old_username or not new_name or not new_username or not new_password:
                logger.error(f"Missing mandatory fields in credential: {credential}")
                continue

            credential['newPassword'] = encrypt(new_password, key)
            valid_credentials.append({
                'oldName': old_name,
                'oldUsername': old_username,
                'newName': new_name,
                'newUrl': new_url,
                'newUsername': new_username,
                'newPassword': credential['newPassword']
            })

        if not valid_credentials:
            raise ValueError("No valid credentials to update. Each credential must include 'oldName', 'oldUsername', 'newName', 'newUsername', and 'newPassword'.")

        # Define the URL for the API endpoint
        url = f"{BASE_URL}/api/update-credentials"
        
        # Prepare the data payload
        data = {"credentials": valid_credentials}
        
        # Send a PUT request to update the batch of credentials
        response = session.put(url, json=data)
        response.raise_for_status()
        
        # Return the server response
        return response.json()
    
    except requests.RequestException as e:
        # Log and raise an error if there is a request-related issue
        logger.error(f"Error updating credentials batch: {e}")
        raise
    
    except ValueError as e:
        # Log and raise an error if the derived key is not found or no valid credentials are provided
        logger.error(f"Value error: {e}")
        raise
    
    except Exception as e:
        # Log and raise any other errors that occur during encryption
        logger.error(f"Error encrypting credentials: {e}")
        raise

def update_credentials_password_only(credentials, session=session):
    """
    Update the passwords of a batch of credentials on the server.

    Args:
        credentials (list of dict): A list of credentials, where each credential is a dictionary with keys 'name', 'username', and 'password'.
        session (requests.Session): A requests session object.

    Returns:
        dict: The JSON response from the server if the update is successful.

    Raises:
        requests.RequestException: If there is an error during the request.
        ValueError: If no valid credentials are provided.
        Exception: For any other errors during the process.
    """
    try:
        valid_credentials = []

        # Validate the credentials
        for credential in credentials:
            name = credential.get('name')
            username = credential.get('username')
            password = credential.get('password')

            if not name or not username or not password:
                logger.error(f"Missing mandatory fields in credential: {credential}")
                continue

            valid_credentials.append({
                'name': name,
                'username': username,
                'password': password
            })

        if not valid_credentials:
            raise ValueError("No valid credentials to update. Each credential must include 'name', 'username', and 'password'.")

        # Define the URL for the API endpoint
        url = f"{BASE_URL}/api/update-password-only"
        
        # Prepare the data payload
        data = {"credentials": valid_credentials}
        
        # Send a PUT request to update the passwords of the batch of credentials
        response = session.put(url, json=data)
        response.raise_for_status()
        
        # Return the server response
        return response.json()
    
        except requests.RequestException as e:
        # Log and raise an error if there is a request-related issue
        logger.error(f"Error updating credentials passwords batch: {e}")
        raise
    
    except ValueError as e:
        # Log and raise an error if no valid credentials are provided
        logger.error(f"Value error: {e}")
        raise
    
    except Exception as e:
        # Log and raise any other errors that occur during the process
        logger.error(f"Error updating credentials passwords: {e}")
        raise

def import_passwords(filename, session=session):
    try:
        logger.info(f"Starting import from file: {filename}")
        with open(filename, 'r') as f:
            reader = csv.DictReader(f)
            credentials_to_add = []
            for row in reader:
                # Check for missing mandatory fields
                if not all(field in row and row[field] for field in ['name', 'username', 'password']):
                    continue  # Skip credentials with missing mandatory fields

                # Use an empty string for the url if it is missing or empty
                url = row['url'] if 'url' in row and row['url'] else ''

                credentials_to_add.append({
                    'name': row['name'],
                    'url': url,
                    'username': row['username'],
                    'password': row['password']
                })
                
            if len(credentials_to_add) > 0:
                logger.info(f"Attempting to add {len(credentials_to_add)} credentials")
                result = add_credentials(credentials_to_add, session=session)
                return result  # Return the result for more detailed handling
            else:
                logger.error("No valid credentials to add from the CSV file")
                return False
    except FileNotFoundError:
        logger.error(f"No file found: {filename}")
        raise
    except Exception as e:
        logger.error(f"Error importing passwords: {e}")
        raise

def export_passwords(filename, session=session):
    """
    Export passwords to a CSV file from the server.

    Args:
        filename (str): The name of the CSV file to write credentials to.
        session (requests.Session): A requests session object.

    Raises:
        ValueError: If the master password or salt is not found.
        Exception: For any other errors during the export process.
    """
    try:
        credentials = get_credentials(session).get('credentials', [])
        if not credentials:
            logger.error("No credentials found to export")
            return

        # Load the stored derived key
        key = load_derived_key()
        if not key:
            raise ValueError("Derived key not found")
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['name', 'url', 'username', 'password'])  # Write header
            for cred in credentials:
                writer.writerow([cred.get('name', ''), cred['url'], cred['username'], cred['password']])
        logger.info(f"Passwords exported to {filename}")
    except Exception as e:
        logger.error(f"Error exporting passwords: {e}")

def change_password(current_password, new_password, session=session):
    """
    Change the user's password, re-encrypt all stored credentials with the new password, and update the server.

    Args:
        current_password (str): The user's current password.
        new_password (str): The user's new password.
        session (requests.Session): A requests session object.

    Returns:
        dict: The JSON response from the server if the password change is successful, or an error message otherwise.
    """
    try:
        # Step 1: Update the password on the server and get the salt in the response
        url = f"{BASE_URL}/api/update-password"
        data = {"currentPassword": current_password, "newPassword": new_password}
        response = session.post(url, json=data)
        response.raise_for_status()
        response_data = response.json()

        if response_data.get("status") != 200:
            return response_data

        # Retrieve the salt from the password update response
        salt = response_data.get("salt")
        if not salt:
            logger.error("Salt not found in update-password response")
            return {"success": False, "message": "Salt not found in update-password response", "status": 500}

        # Step 2: Retrieve all credentials
        credentials_response = get_credentials(session)
        if credentials_response.get("status") != 200:
            logger.error("Failed to retrieve credentials during password change.")
            return {"success": False, "message": "Failed to retrieve credentials during password change.", "status": 500}

        credentials = credentials_response.get('credentials', [])

        # Step 3: Derive the new key using the new password and the retrieved salt
        new_key = derive_key(new_password, base64.b64decode(salt))

        # Step 4: Re-encrypt all credentials with the new key
        updated_credentials = []
        for cred in credentials:
            re_encrypted_password = encrypt(cred['password'], new_key)
            updated_credentials.append({
                'name': cred['name'],
                'username': cred['username'],
                'password': re_encrypted_password
            })

        # Step 5: Update credentials on the server
        update_response = update_credentials_password_only(updated_credentials, session)
        if update_response.get("status") != 200:
            logger.error("Failed to update credentials during password change.")
            return {"success": False, "message": "Failed to update credentials during password change.", "status": 500}

        # Step 6: Save the new master password and derived key

        save_derived_key(new_key)

        return {"success": True, "message": "Password changed successfully", "status": 200}
    except requests.RequestException as e:
        logger.error(f"Error changing password: {e}")
        return {"success": False, "message": f"Error changing password: {e}", "status": 500}
    except Exception as e:
        logger.error(f"Error during password change process: {e}")
        return {"success": False, "message": f"Error during password change process: {e}", "status": 500}
