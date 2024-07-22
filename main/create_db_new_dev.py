import sqlite3

# Initialize the database connection
conn = sqlite3.connect('new_devices.db')
cursor = conn.cursor()

# Step 1: Create a new table with the desired schema
cursor.execute('''
    CREATE TABLE IF NOT EXISTS unencrypted_data (
        mac_address TEXT PRIMARY KEY,
        unencrypted_data_flow TEXT,
        unencrypted_count TEXT,
        protocol TEXT
     
    )
''')



# Commit the changes
conn.commit()

# Close the connection
conn.close()