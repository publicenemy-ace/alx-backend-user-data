#!/usr/bin/env python3
"""DB module
"""
from sqlalchemy import create_engine
import sqlalchemy.exc
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound

from user import Base, User



class DB:
    """DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """Adds user to the database

        Args:
            email (str): the user email
            hashed_password: the hashed user password

        Returns:
            The created user
        """
        try:
            new_user = User(email=email, hashed_password=hashed_password)
            self.save(new_user)
            self.commit()
        except Exception:
            self._session.rollback()
            new_user = None
        # return the newly created user object
        return new_user

    # save user to database
    def save(self, instance):
        """saves instance to the session

        Args:
            instance (obj): instance to save
        """
        self._session.add(instance)

    def commit(self):
        """commit chanes to the database
        """
        self._session.commit()

    def find_user_by(self, **kwargs) -> User:
        """Takes arbitrary keyword arguments

        Returns:
            The first row found in the users table
            as filtered by the method's input arguments
        """
        try:
            return self._session.query(User).filter_by(**kwargs).one()
        except NoResultFound:
            raise NoResultFound
        except InvalidRequestError:
            raise InvalidRequestError

    def update_user(self, user_id: int, **kwargs) -> None:
        """Finds a user by id and then updates their data
        as provided in kwargs

        Args:
            user_id (int): user_id to find
            **Kwargs (dict): keyword arguments to update
        """
        found_user = self.find_user_by(id=user_id)

        # Loop over the provided kwargs to see if follow model
        for key, value in kwargs.items():
            # check if the attribute exists in the user model
            if not hasattr(found_user, key):
                raise ValueError

            # Update the attribute with teh new value
            setattr(found_user, key, value)

        # Commit changes to the db
        self.commit()
