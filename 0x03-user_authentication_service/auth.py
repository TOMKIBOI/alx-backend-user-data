#!/usr/bin/env python3
"""Auth module
"""
import bcrypt
import uuid
from db import DB
from user import User
from typing import Union
from sqlalchemy.orm.exc import NoResultFound


def _hash_password(password: str) -> bytes:
    """Hashes the input password using bcrypt.

    Args:
        password: The password to be hashed.

    Returns:
        The hashed password as bytes.

    """
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password


def _generate_uuid() -> str:
    """Generates a new UUID.

    Returns:
        A string representation of the new UUID.

    """
    return str(uuid.uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Registers a new user.

        Args:
            email: The email of the user.
            password: The password of the user.

        Returns:
            The User object representing the registered user.

        Raises:
            ValueError: If a user already exists with the passed email.

        """
        try:
            user = self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists.")
        except NoResultFound:
            hashed_password = _hash_password(password)
            user = self._db.add_user(
                email=email, hashed_password=hashed_password)
            return user

    def valid_login(self, email: str, password: str) -> bool:
        """Validates if a login is valid.

        Args:
            email: The email of the user.
            password: The password of the user.

        Returns:
            True if the login is valid, False otherwise.

        """
        try:
            user = self._db.find_user_by(email=email)
            if bcrypt.checkpw(password.encode(), user.hashed_password):
                return True
            else:
                return False
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """Creates a new session for the user.

        Args:
            email: The email of the user.

        Returns:
            The session ID as a string.

        """
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """Gets the user associated with a session ID.

        Args:
            session_id: The session ID.

        Returns:
            The User object associated with the session
            ID, or None if not found.

        """
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Destroys the session for the user.

        Args:
            user_id: The ID of the user.

        Returns:
            None.

        """
        self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """Generates a reset password token for the user.

        Args:
            email: The email of the user.

        Returns:
            The reset password token as a string.

        Raises:
            ValueError: If the user does not exist.

        """
        try:
            user = self._db.find_user_by(email=email)
            reset_token = _generate_uuid()
            self._db.update_user(user.id, reset_token=reset_token)
            return reset_token
        except NoResultFound:
            raise ValueError(f"User {email} does not exist.")

    def update_password(self, reset_token: str, password: str) -> None:
        """Updates the user's password.

        Args:
            reset_token: The reset password token.
            password: The new password.

        Returns:
            None.

        Raises:
            ValueError: If the user does not exist.

        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            hashed_password = _hash_password(password)
            self._db.update_user(
                user.id,
                hashed_password=hashed_password,
                reset_token=None)
        except NoResultFound:
            raise ValueError("User does not exist.")
