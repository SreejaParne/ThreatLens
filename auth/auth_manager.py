import json
import os
from werkzeug.security import generate_password_hash, check_password_hash

class AuthManager:
    def __init__(self, user_file="auth/users.json"):
        self.user_file = user_file

        if not os.path.exists(user_file):
            with open(user_file, "w") as f:
                json.dump([], f)

        with open(user_file, "r") as f:
            self.users = json.load(f)

    def save_users(self):
        with open(self.user_file, "w") as f:
            json.dump(self.users, f, indent=4)

    # ---------------- REGISTER ----------------
    def register(self, full_name, org, designation, email, mobile, role, username, password):
        username = username.strip()

        # Check duplicate
        for user in self.users:
            if user["username"] == username:
                return False, "Username already exists"

        hashed_password = generate_password_hash(password)

        new_user = {
            "full_name": full_name,
            "organisation": org,
            "designation": designation,
            "email": email,
            "mobile": mobile,
            "role": role,
            "username": username,
            "password": hashed_password
        }

        self.users.append(new_user)
        self.save_users()
        return True, "Registration successful"

    # ---------------- LOGIN ----------------
    def authenticate(self, username, password):
        username = username.strip()
        password = password.strip()

        for user in self.users:
            if user["username"] == username:
                if check_password_hash(user["password"], password):
                    return user["role"]

        return None
    
    def get_user(self, username):
        for user in self.users:
            if user["username"] == username:
                return user
        return None
    
    def update_user(self, username, full_name, org, designation):
        for user in self.users:
            if user["username"] == username:
                user["full_name"] = full_name
                user["organisation"] = org
                user["designation"] = designation
                self.save_users()
                return True
        return False
    
    def get_all_users(self):
        return self.users
    
    def delete_user(self, username):
        self.users = [u for u in self.users if u["username"] != username]
        self.save_users()
        
    def change_password(self, username, old_password, new_password):
        for user in self.users:
            if user["username"] == username:
            # verify old password
                if check_password_hash(user["password"], old_password):
                    user["password"] = generate_password_hash(new_password)
                    self.save_users()
                    return True, "Password updated successfully"
                else:
                    return False, "Old password incorrect"
        return False, "User not found"
    
    def update_password(self, username, new_password):
        import hashlib

        if username in self.users:
            hashed = hashlib.sha256(new_password.encode()).hexdigest()
            self.users[username]["password"] = hashed

            with open("auth/users.json", "w") as f:
                json.dump(self.users, f, indent=4)

            return True
        return False