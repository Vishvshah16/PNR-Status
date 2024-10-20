import subprocess
import tkinter as tk
from tkinter import messagebox, scrolledtext, Listbox, Frame
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from base64 import b64encode
from requests import post
from requests.exceptions import RequestException
from json import loads
import threading

REQUIRED_PACKAGES = ['cryptography', 'requests']

# Check if the required packages are installed
for package in REQUIRED_PACKAGES:
    try:
        __import__(package)
    except ImportError:
        subprocess.check_call(['pip', 'install', package])

# Encrypt PNR function
def encrypt_pnr(pnr):
    data = bytes(pnr, 'utf-8')
    backend = default_backend()
    padder = padding.PKCS7(128).padder()
    data = padder.update(data) + padder.finalize()
    key = b'8080808080808080'
    iv = b'8080808080808080'
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(data) + encryptor.finalize()
    enc_pnr = b64encode(ct)
    return enc_pnr.decode('utf-8')

# Function to display PNR status in the GUI
def display_pnr_status(json_data):
    try:
        text_area.config(state=tk.NORMAL)
        text_area.delete(1.0, tk.END)
        
        if json_data.get("status") == "failed":
            text_area.insert(tk.END, "PNR Not Found or Invalid.\n")
            text_area.config(state=tk.DISABLED)
            return

        boarding_station = json_data["BrdPointName"]
        destination_station = json_data["DestStnName"]
        quota = json_data["quota"]
        class_name = json_data["className"]
        train_number = json_data["trainNumber"]
        train_name = json_data["trainName"]
        date_of_journey = json_data["dateOfJourney"]
        
        text_area.insert(tk.END, "PNR STATUS\n")
        text_area.insert(tk.END, "----------------------------------------\n")
        text_area.insert(tk.END, f"{boarding_station} -> {destination_station}\n")
        text_area.insert(tk.END, f"{train_number} - {train_name}\n")
        text_area.insert(tk.END, f"Quota: {quota}\n")
        text_area.insert(tk.END, f"Journey Class: {class_name}\n")
        text_area.insert(tk.END, f"Date Of Journey: {date_of_journey}\n")
        text_area.insert(tk.END, "----------------------------------------\n\n")
        
        if "passengerList" not in json_data or json_data["passengerList"] is None:
            text_area.insert(tk.END, "No passenger information available.\n")
            text_area.config(state=tk.DISABLED)
            return
        
        headers = f"{'Passenger':<10} {'Status':<25} {'Coach':<10} {'Berth':<15}\n"
        text_area.insert(tk.END, headers)
        text_area.insert(tk.END, "-"*65 + "\n")
        
        for passenger in json_data["passengerList"]:
            passenger_serial_number = passenger["passengerSerialNumber"]
            current_status = passenger["currentStatus"]
            current_coach_id = passenger.get("currentCoachId", "N/A")
            current_berth_no = passenger.get("currentBerthNo", "N/A")
            current_berth_code = passenger.get("bookingBerthCode", "N/A")
            
            if "CNF" in current_status:
                berth_info = f"{current_berth_no} ({current_berth_code})"
            else:
                berth_info = current_berth_no

            row = f"{passenger_serial_number:<10} {current_status:<25} {current_coach_id:<10} {berth_info:<15}\n"
            text_area.insert(tk.END, row)
        
        text_area.insert(tk.END, "-"*65 + "\n")
        text_area.config(state=tk.DISABLED)
    except KeyError as e:
        messagebox.showerror("Error", f"Invalid JSON data format. Missing key: {str(e)}")
        text_area.config(state=tk.DISABLED)

# Function to fetch PNR status (run in a separate thread)
def fetch_pnr_status(pnr=None):
    fetch_button.config(text="Loading...", state=tk.DISABLED)

    if pnr is None:
        pnr = pnr_entry.get()

    if len(pnr) != 10 or not pnr.isdigit():
        messagebox.showerror("Error", "PNR should be 10 digits.")
        fetch_button.config(text="Check PNR Status", state=tk.NORMAL)
        return

    encrypted_pnr = encrypt_pnr(pnr)

    json_data = {
        'pnrNumber': encrypted_pnr,
    }

    try:
        response = post('https://railways.easemytrip.com/Train/PnrchkStatus', json=json_data, verify=True)
        response.raise_for_status()
        json_data = loads(response.content)
        display_pnr_status(json_data)

        if pnr not in pnr_history.get(0, tk.END):
            pnr_history.insert(tk.END, pnr)
    except (RequestException) as e:
        messagebox.showerror("Connection Error", f"An error occurred while connecting to the API: {str(e)}")
    except ValueError as e:
        messagebox.showerror("Error", f"Invalid response from the API. Response cannot be parsed as JSON: {str(e)}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")
    finally:
        fetch_button.config(text="Check PNR Status", state=tk.NORMAL)

# Function to handle selecting PNR from history and fetching its status
def show_selected_pnr_status(event):
    selected_pnr = pnr_history.get(tk.ACTIVE)
    pnr_entry.delete(0, tk.END)
    pnr_entry.insert(0, selected_pnr)
    fetch_pnr_status(selected_pnr)

# Function to delete the selected PNR from history
def delete_selected_pnr():
    selected_index = pnr_history.curselection()
    if not selected_index:
        messagebox.showwarning("Warning", "Please select a PNR to delete.")
        return
    pnr_history.delete(selected_index)

# Function to clear the PNR entry box and text area
def clear_fields():
    pnr_entry.delete(0, tk.END)
    text_area.config(state=tk.NORMAL)
    text_area.delete(1.0, tk.END)
    text_area.config(state=tk.DISABLED)

# GUI setup
root = tk.Tk()
root.title("PNR Status Checker")
root.geometry("600x600")
root.configure(bg="#f0f0f0")  # Set a background color

# Center the window on the screen
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
x_coordinate = (screen_width // 2) - (300)  # 600 / 2
y_coordinate = (screen_height // 2) - (300)  # 600 / 2
root.geometry(f"600x600+{x_coordinate}+{y_coordinate}")
root.resizable(False, False)

# PNR input
pnr_label = tk.Label(root, text="Enter PNR Number:", bg="#f0f0f0")
pnr_label.pack(pady=10)
pnr_entry = tk.Entry(root, width=20)
pnr_entry.pack(pady=10)

# Button to fetch PNR status
fetch_button = tk.Button(root, text="Check PNR Status", command=lambda: threading.Thread(target=fetch_pnr_status).start())
fetch_button.pack(pady=5)

# Button to delete selected PNR
delete_button = tk.Button(root, text="Delete Selected PNR", command=delete_selected_pnr)
delete_button.pack(pady=5)

# Button to clear fields
clear_button = tk.Button(root, text="Clear", command=clear_fields)
clear_button.pack(pady=5)

# Text area to display the results (read-only)
text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=70, height=15, font=("Courier", 10))
text_area.pack(pady=10)

# Frame for PNR history
history_frame = Frame(root, bg="#f0f0f0")
history_frame.pack(pady=10)

# History listbox
pnr_history_label = tk.Label(history_frame, text="PNR History:", bg="#f0f0f0")
pnr_history_label.pack(side=tk.TOP, pady=5)
pnr_history = Listbox(history_frame, height=5, width=20)
pnr_history.pack(side=tk.LEFT)

# Bind history selection to show selected PNR
pnr_history.bind('<<ListboxSelect>>', show_selected_pnr_status)

# Start the GUI main loop
root.mainloop()
