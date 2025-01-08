import sqlite3

# Connect to the database or create it
conn = sqlite3.connect('example.db')
cursor = conn.cursor()

# Create a users table
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL
)
''')

# Insert dummy data
cursor.executemany('''
INSERT INTO users (username, password) VALUES (?, ?)
''', [
    ('admin', 'password123'),
    ('user1', 'user1password'),
    ('user2', 'user2password'),
])

# Commit and close
conn.commit()
conn.close()

print("Database setup complete!")
