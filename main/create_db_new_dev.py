import sqlite3

# Initialize the database connection
conn = sqlite3.connect('new_devices.db')
cursor = conn.cursor()

# Step 1: Create a new table with the desired schema
cursor.execute(
    "DELETE FROM url_alerts_new")



# Commit the changes
conn.commit()

# Close the connection
conn.close()