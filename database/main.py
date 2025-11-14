import sqlite3
from datetime import datetime

from schema import Schema

DB_NAME = "database.db"


def add_client(user_name, IP, status, time_stamp):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR IGNORE INTO Client (user_name, IP, status, time_stamp) VALUES (?, ?, ?, ?)",
        (user_name, IP, status, time_stamp),
    )
    conn.commit()
    conn.close()


def remove_client(user_name):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM Client WHERE user_name = ?", (user_name,))
    conn.commit()
    conn.close()


def add_image(user_name, image_id, image):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR IGNORE INTO Image (user_name, image_id, image) VALUES (?, ?, ?)",
        (user_name, image_id, image),
    )
    conn.commit()
    conn.close()


def remove_image(image_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM Image WHERE image_id = ?", (image_id,))
    conn.commit()
    conn.close()


def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Create tables
    cursor.execute(Schema.Client())
    cursor.execute(Schema.Image())

    conn.commit()
    conn.close()

    print("Database initialized with Client and Image tables.")


if __name__ == "__main__":

    # Initialize the database
    init_db()
