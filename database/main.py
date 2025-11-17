import sqlite3
from datetime import datetime
from flask import Flask, request, jsonify
import threading
import time
import base64
from PIL import Image
import io


from schema import Schema

DB_NAME = "database.db"

app = Flask(__name__)


def add_client(user_name, ip_addr):
    time_stamp = datetime.now().isoformat()
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR IGNORE INTO Client (user_name, ip_addr, status, time_stamp) VALUES (?, ?, ?, ?)",
        (user_name, ip_addr, 1, time_stamp),
    )
    cursor.execute("SELECT * FROM Client")
    print(cursor.fetchall())
    conn.commit()
    conn.close()


def remove_client(user_name):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM Client WHERE user_name = ?", (user_name,))
    conn.commit()
    conn.close()


def update_timestamp(user_name):
    time_stamp = datetime.now().isoformat()
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE Client SET time_stamp = ?, status = 1 WHERE user_name = ?",
        (time_stamp, user_name),
    )
    conn.commit()
    conn.close()


def add_image(image_name, image_bytes, user_name):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    print("--Adding image--")
    print(f'Image name: image_name')
    print(f'Username: {user_name}')
    # print(image_bytes)
    # print(type(image_bytes))

    raw_bytes = base64.b64decode(image_bytes)

    cursor.execute(
        "INSERT OR IGNORE INTO Image (image_name, image_bytes, user_name) VALUES (?, ?, ?)",
        (image_name, raw_bytes, user_name),
    )
    conn.commit()

    # Display the image
    cursor.execute("SELECT image_bytes FROM Image WHERE image_name = ?", (image_name,))
    row = cursor.fetchone()
    if row:
        img_data = row[0]  # This is the BLOB
        img = Image.open(io.BytesIO(img_data))
        img.show()  # Opens the image in the default image viewer

    conn.close()


def remove_image(image_name):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM Image WHERE image_name = ?", (image_name,))
    conn.commit()
    conn.close()


def client_status_worker():
    """Worker that sets status=0 for clients inactive > 10 seconds."""
    while True:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        now = datetime.now()
        cursor.execute("SELECT user_name, time_stamp FROM Client")
        clients = cursor.fetchall()
        for user_name, ts in clients:
            ts_dt = datetime.fromisoformat(ts)
            if (now - ts_dt).total_seconds() > 10:

                print("Status should change:")
                cursor.execute("SELECT * FROM Client")
                print(f'Before: {cursor.fetchall()}')

                cursor.execute(
                    "UPDATE Client SET status = 0 WHERE user_name = ?", (user_name,)
                )

                cursor.execute("SELECT * FROM Client")
                print(f'After: {cursor.fetchall()}')

        conn.commit()
        conn.close()
        time.sleep(10)


def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute(Schema.Client())
    cursor.execute(Schema.Image())

    conn.commit()
    conn.close()
    print("Database initialized with Client and Image tables.")


@app.route('/api', methods=['POST'])
def handle_request():
    try:
        data = request.get_json()
        operation = data.get('operation')

        if operation == 'add_client':
            add_client(
                data.get('user_name'),
                data.get('ip_addr'),
            )
            return jsonify({'status': 'success', 'message': 'Client added'}), 200

        elif operation == 'update_timestamp':
            update_timestamp(
                data.get('user_name'),
            )
            return jsonify({'status': 'success', 'message': 'Timestamp updated'}), 200

        elif operation == 'remove_client':
            remove_client(data.get('user_name'))
            return jsonify({'status': 'success', 'message': 'Client removed'}), 200

        elif operation == 'add_image':
            add_image(
                data.get('image_name'),
                data.get('image_bytes'),
                data.get('user_name'),
            )
            return jsonify({'status': 'success', 'message': 'Image added'}), 200

        elif operation == 'remove_image':
            remove_image(data.get('image_name'))
            return jsonify({'status': 'success', 'message': 'Image removed'}), 200

        else:
            return jsonify({'status': 'error', 'message': 'Unknown operation'}), 400

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


if __name__ == "__main__":
    # Initialize database
    init_db()

    # Run worker thread
    # threading.Thread(target=client_status_worker, daemon=True).start()

    # Run flask server
    app.run(host='127.0.0.1', port=5000)
