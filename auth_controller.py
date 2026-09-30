import hashlib

from database import get_connection
from werkzeug.security import check_password_hash, generate_password_hash


class AuthController:
    def __init__(self, db_path=None):
        self.db_path = db_path

    def login(self, email, password):
        conn = get_connection(sqlite_path=self.db_path)
        try:
            user = conn.execute(
                "SELECT * FROM users WHERE lower(email)=lower(?)",
                (email,),
            ).fetchone()
        finally:
            conn.close()
        valid = False
        if user:
            valid = check_password_hash(user["password_hash"], password) or user["password_hash"] == hashlib.sha256(password.encode()).hexdigest()
        if valid and (user["account_status"] or "ACTIVE") == "ACTIVE":
            return True, dict(user)
        if valid and (user["account_status"] or "ACTIVE") == "PENDING":
            return False, "Please verify your email before logging in."
        return False, "Incorrect email or password."

    @staticmethod
    def password_hash(password):
        return generate_password_hash(password)

    @staticmethod
    def security_answer_hash(answer):
        return generate_password_hash(answer.strip().casefold())

    @staticmethod
    def check_security_answer(answer, hashed):
        return bool(hashed) and check_password_hash(hashed, answer.strip().casefold())
