import tkinter as tk
from tkinter import messagebox

def xor_encrypt(text, key):
    encrypted = ""
    for char, key_char in zip(text, key):
        encrypted += chr(ord(char) ^ ord(key_char))
    return encrypted

def custom_hash(data):
    hash_value = 0
    prime = 31  # A prime number for mixing

    for char in data:
        hash_value = (hash_value * prime + ord(char)) % (2**32)  # Modulo to fit in 32 bits

    return hash_value

class Block:
    def __init__(self, index, previous_hash, timestamp, transactions, merkle_root):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = transactions
        self.merkle_root = merkle_root
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_data = str(self.index) + str(self.previous_hash) + str(self.timestamp) + str(self.transactions) + str(self.merkle_root)
        return custom_hash(block_data)

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        return Block(0, "0", "01/01/2023", [], "0")

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, new_block):
        new_block.previous_hash = self.get_latest_block().hash
        new_block.hash = new_block.calculate_hash()
        self.chain.append(new_block)

def user_exists(username):
    try:
        with open(f"{username}.txt", "r"):
            return True
    except FileNotFoundError:
        return False

def register_user():
    username = username_entry.get()
    password = password_entry.get()

    if user_exists(username):
        messagebox.showerror("Error", "User already exists")
        return

    try:
        with open(f"{username}.txt", "w") as file:
            encrypted_password = xor_encrypt(password, "mysecretkey")
            file.write(f"{encrypted_password}\n0")  # Save encrypted password and money count
        messagebox.showinfo("Success", "User registered successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Registration failed: {str(e)}")

def login_user():
    username = username_entry.get()
    password = password_entry.get()

    try:
        with open(f"{username}.txt", "r") as file:
            stored_password = file.readline()[:-1]
            encrypted_password = xor_encrypt(stored_password, "mysecretkey")

            if password == encrypted_password:
                messagebox.showinfo("Success", "Login successful!")
                open_user_window(username)
            else:
                messagebox.showerror("Error", "Invalid password")
    except FileNotFoundError:
        messagebox.showerror("Error", "User not found")
    except Exception as e:
        messagebox.showerror("Error", f"Login failed: {str(e)}")

def open_user_window(username):
    user_window = tk.Toplevel(root)
    user_window.title(f"Welcome, {username}")

    money_label_var = tk.StringVar()

    def update_money_label():
    # Read user's encrypted password and money count from file
        with open(f"{username}.txt", "r") as file:
            lines = file.read().splitlines()

        if len(lines) == 2:
            encrypted_password, money_count = lines
            money_count = int(money_count)
            money_label_var.set(f"Welcome, {username}!\nMoney: ${money_count}")
        else:
            # Handle the case where there are not enough lines in the file
            messagebox.showerror("Error", "Invalid file format")


    money_label = tk.Label(user_window, textvariable=money_label_var)
    money_label.pack(pady=20)

    add_money_label = tk.Label(user_window, text="Add money:")
    add_money_label.pack(pady=5)

    add_money_entry = tk.Entry(user_window)
    add_money_entry.pack(pady=5)

    def add_money():
        nonlocal money_label_var
        try:
            amount = int(add_money_entry.get())
            if amount < 0:
                messagebox.showerror("Error", "Please enter a positive amount")
                return

            # Update money count in the user's file
            with open(f"{username}.txt", "r+") as file:
                encrypted_password, money_count = file.read().splitlines()

                money_count = int(money_count)
                money_count += amount

                # Move the cursor to the beginning to overwrite the file
                file.seek(0)
                file.truncate()

                file.write(f"{encrypted_password}\n{money_count}")

            messagebox.showinfo("Success", f"Added ${amount} to your account!")
            update_money_label()

            # Add blockchain logic
            transactions = [f"{username} added ${amount} to their account"]
            merkle_root = custom_hash("".join(transactions))
            new_block = Block(len(blockchain.chain), blockchain.get_latest_block().hash, "timestamp_placeholder", transactions, merkle_root)
            blockchain.add_block(new_block)
            messagebox.showinfo("Success", f"Transaction added to the blockchain!")

        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number")

    add_money_button = tk.Button(user_window, text="Add Money", command=add_money)
    add_money_button.pack(pady=10)

    def share_money():
        nonlocal money_label_var
        share_username = share_username_entry.get()
        try:
            share_amount = int(share_amount_entry.get())

            # Read the current user's file
            with open(f"{username}.txt", "r+") as file:
                encrypted_password, money_count = file.read().splitlines()

                money_count = int(money_count)
                if share_amount < 0 or share_amount > money_count:
                    messagebox.showerror("Error", "Invalid share amount")
                    return

                money_count -= share_amount

                # Move the cursor to the beginning to overwrite the file
                file.seek(0)
                file.truncate()

                file.write(f"{encrypted_password}\n{money_count}")

            # Read the shared user's file
            with open(f"{share_username}.txt", "r+") as file:
                encrypted_password, shared_money_count = file.read().splitlines()

                shared_money_count = int(shared_money_count)
                shared_money_count += share_amount

                # Move the cursor to the beginning to overwrite the file
                file.seek(0)
                file.truncate()

                file.write(f"{encrypted_password}\n{shared_money_count}")

            messagebox.showinfo("Success", f"Shared ${share_amount} with {share_username}!")
            update_money_label()

            # Add blockchain logic
            transactions = [f"{username} shared ${share_amount} with {share_username}"]
            merkle_root = custom_hash("".join(transactions))
            new_block = Block(len(blockchain.chain), blockchain.get_latest_block().hash, "timestamp_placeholder", transactions, merkle_root)
            blockchain.add_block(new_block)
            messagebox.showinfo("Success", f"Transaction added to the blockchain!")

        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number")


    share_money_label = tk.Label(user_window, text="Share money with:")
    share_money_label.pack(pady=5)

    share_username_entry = tk.Entry(user_window)
    share_username_entry.pack(pady=5)

    share_amount_label = tk.Label(user_window, text="Amount:")
    share_amount_label.pack(pady=5)

    share_amount_entry = tk.Entry(user_window)
    share_amount_entry.pack(pady=5)

    share_money_button = tk.Button(user_window, text="Share Money", command=share_money)
    share_money_button.pack(pady=10)

    update_money_label()  # Initial update of money label

# Create instances of Blockchain
blockchain = Blockchain()

root = tk.Tk()
root.title("Login, Register, and Blockchain Demo")

tk.Label(root, text="Username:").pack(pady=5)
username_entry = tk.Entry(root)
username_entry.pack(pady=5)

tk.Label(root, text="Password:").pack(pady=5)
password_entry = tk.Entry(root, show="*")
password_entry.pack(pady=5)

register_button = tk.Button(root, text="Register", command=register_user)
register_button.pack(pady=10)

login_button = tk.Button(root, text="Login", command=login_user)
login_button.pack(pady=10)

root.mainloop()

