import sqlite3

def connect():

    connection = sqlite3.connect("database/behavior.db")

    return connection