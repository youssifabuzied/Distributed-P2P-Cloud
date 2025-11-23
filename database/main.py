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

    cursor.execute("""
        INSERT INTO Client (user_name, ip_addr, status, time_stamp)
        VALUES (?, ?, 1, ?)
        ON CONFLICT(user_name)
        DO UPDATE SET 
            status = 1,
            ip_addr = excluded.ip_addr,
            time_stamp = excluded.time_stamp;
    """, (user_name, ip_addr, time_stamp))

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

def fetch_active_users():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT user_name, ip_addr FROM Client WHERE status = 1")
    users = cursor.fetchall()
    conn.close()
    return users

def fetch_user_images(user_name):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Check if user is online (status = 1)
    cursor.execute("SELECT status FROM Client WHERE user_name = ?", (user_name,))
    result = cursor.fetchone()
    
    if result is None:
        conn.close()
        return False, []  # User doesn't exist
    
    is_online = result[0] == 1
    
    if not is_online:
        conn.close()
        return False, []  # User is offline
    
    # Fetch images with their bytes for this user
    cursor.execute("SELECT image_name, image_bytes FROM Image WHERE user_name = ?", (user_name,))
    images = []
    for row in cursor.fetchall():
        image_name = row[0]
        image_bytes = row[1]  # BLOB data
        # Encode bytes to base64 for JSON transport
        image_bytes_b64 = base64.b64encode(image_bytes).decode('utf-8')
        images.append({
            'image_name': image_name,
            'image_bytes': image_bytes_b64
        })
    print("fetch_images_done")
    conn.close()
    return True, images

def request_image_access(owner, viewer, image_name, prop_views):
    """
    Create an image access request record with status=2 (pending/requested)
    
    Args:
        owner: Username of the image owner
        viewer: Username requesting access
        image_name: Name of the image
        prop_views: Proposed number of views
    
    Returns:
        bool: True if successful, False otherwise
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    try:
        # Check if owner exists and is online
        cursor.execute("SELECT status FROM Client WHERE user_name = ?", (owner,))
        owner_result = cursor.fetchone()
        
        if owner_result is None:
            print(f"Error: Owner '{owner}' does not exist")
            conn.close()
            return False
        
        # Check if viewer exists
        cursor.execute("SELECT user_name FROM Client WHERE user_name = ?", (viewer,))
        viewer_result = cursor.fetchone()
        
        if viewer_result is None:
            print(f"Error: Viewer '{viewer}' does not exist")
            conn.close()
            return False
        
        # Check if image exists for this owner
        cursor.execute(
            "SELECT image_name FROM Image WHERE image_name = ? AND user_name = ?",
            (image_name, owner)
        )
        image_result = cursor.fetchone()
        
        if image_result is None:
            print(f"Error: Image '{image_name}' does not exist for owner '{owner}'")
            conn.close()
            return False
        
        # Insert or update the access request with status=2
        cursor.execute("""
            INSERT INTO ImageAccess (status, owner, viewer, image_name, prop_views, accep_views)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(owner, image_name, viewer) 
            DO UPDATE SET 
                status = excluded.status,
                prop_views = excluded.prop_views,
                accep_views = 0
        """, (2, owner, viewer, image_name, prop_views, 0))
        
        conn.commit()
        print(f"Access request created: {viewer} -> {owner}'s '{image_name}' ({prop_views} views)")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"Error creating access request: {e}")
        conn.close()
        return False


def get_pending_requests(username):
    """
    Get all pending access requests for a user (as owner)
    
    Args:
        username: Username of the owner
    
    Returns:
        list: List of tuples (viewer, image_name, prop_views)
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT viewer, image_name, prop_views 
        FROM ImageAccess 
        WHERE owner = ? AND status = 2
    """, (username,))
    
    requests = cursor.fetchall()
    conn.close()
    return requests


def get_my_requests(username):
    """
    Get all access requests made by a user (as viewer)
    
    Args:
        username: Username of the viewer
    
    Returns:
        list: List of tuples (owner, image_name, prop_views, status)
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT owner, image_name, prop_views, status
        FROM ImageAccess 
        WHERE viewer = ?
    """, (username,))
    
    requests = cursor.fetchall()
    conn.close()
    return requests

def approve_or_reject_access_request(owner, viewer, image_name, accep_views):
    """
    Approve or reject an access request
    
    Args:
        owner: Username of the image owner
        viewer: Username requesting access
        image_name: Name of the image
        accep_views: Accepted views (-1 to reject, >0 to approve)
    
    Returns:
        bool: True if successful, False otherwise
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    try:
        # Check if request exists with status=2 (pending)
        cursor.execute("""
            SELECT prop_views FROM ImageAccess 
            WHERE owner = ? AND viewer = ? AND image_name = ? AND status = 2
        """, (owner, viewer, image_name))
        
        result = cursor.fetchone()
        
        if result is None:
            print(f"Error: No pending request found for {viewer} -> {owner}'s '{image_name}'")
            conn.close()
            return False
        
        # Determine status: 0 = rejected, 1 = approved
        if accep_views == -1:
            status = 0
            accep_views = 0
            action = "rejected"
        elif accep_views > 0:
            status = 1
            action = "approved"
        else:
            print(f"Error: Invalid accep_views value: {accep_views}")
            conn.close()
            return False
        
        # Update the request
        cursor.execute("""
            UPDATE ImageAccess 
            SET status = ?, accep_views = ?
            WHERE owner = ? AND viewer = ? AND image_name = ?
        """, (status, accep_views, owner, viewer, image_name))
        
        conn.commit()
        print(f"Access request {action}: {viewer} -> {owner}'s '{image_name}' ({accep_views} views)")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"Error updating access request: {e}")
        conn.close()
        return False

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
            if (now - ts_dt).total_seconds() > 30:

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
        time.sleep(30)


def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute(Schema.Client())
    cursor.execute(Schema.Image())
    cursor.execute(Schema.ImageAccess())


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
        
        elif operation == 'fetch_active_users':
            users = fetch_active_users()
            users_list = [{'user_name': u[0], 'ip_addr': u[1]} for u in users]
            return jsonify({'status': 'success', 'users': users_list}), 200
        
        elif operation == 'fetch_user_images':
            is_online, images = fetch_user_images(data.get('user_name'))
            return jsonify({
                'status': 'success',
                'is_online': is_online,
                'images': images
            }), 200
        
        elif operation == 'request_image_access':
            owner = data.get('owner')
            viewer = data.get('viewer')
            image_name = data.get('image_name')
            prop_views = data.get('prop_views')
            
            success = request_image_access(owner, viewer, image_name, prop_views)
            
            if success:
                return jsonify({
                    'status': 'success',
                    'message': f'Access request created for {image_name}'
                }), 200
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to create access request'
                }), 400

        elif operation == 'get_pending_requests':
            requests = get_pending_requests(data.get('user_name'))
            return jsonify({
                'status': 'success',
                'requests': [
                    {'viewer': r[0], 'image_name': r[1], 'prop_views': r[2]}
                    for r in requests
                ]
            }), 200

        elif operation == 'get_my_requests':
            requests = get_my_requests(data.get('user_name'))
            return jsonify({
                'status': 'success',
                'requests': [
                    {'owner': r[0], 'image_name': r[1], 'prop_views': r[2], 'status': r[3]}
                    for r in requests
                ]

            }), 200
        
        elif operation == 'approve_or_reject_access':
            owner = data.get('owner')
            viewer = data.get('viewer')
            image_name = data.get('image_name')
            accep_views = data.get('accep_views')
            
            success = approve_or_reject_access_request(owner, viewer, image_name, accep_views)
            
            if success:
                action = "rejected" if accep_views == -1 else "approved"
                return jsonify({
                    'status': 'success',
                    'message': f'Access request {action}'
                }), 200
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to update access request'
                }), 400

        else:
            return jsonify({'status': 'error', 'message': 'Unknown operation'}), 400

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


if __name__ == "__main__":
    # Initialize database
    init_db()

    # Run worker thread
    threading.Thread(target=client_status_worker, daemon=True).start()

    # Run flask server
    app.run(host='127.0.0.1', port=5000)
