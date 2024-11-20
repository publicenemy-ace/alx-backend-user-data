#!/usr/bin/env python3
"""SQLA Alchemy User Model"""
# import declaravive_base
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String

# create a base class
Base = declarative_base()


class User(Base):
    """User model for the users table"""
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    email = Column(String(250), nullable=False)
    hashed_password = Column(String(250), nullable=False)
    session_id = Column(String(250), nullable=True)
    reset_token = Column(String(250), nullable=True)

    def __repr__(self):
        """Standard string represnetation for the user object"""
        return "<User(email='%s', session_id='%s')>" % (
            self.email, self.session_id)
