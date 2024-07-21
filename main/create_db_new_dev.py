import sqlite3
import json

# Initialize the database connection
conn = sqlite3.connect('new_devices.db')
cursor = conn.cursor()



# Update the connected_devices field in the database with the JSON string
# mac_address = 'ae:bc:da:7a:65:cb'
cursor.execute(
    "DELETE FROM new_devices WHERE mac_adress = ?",('30:d1:6b:40:df:5a',) 
)



conn.commit()




# Close the database connection
conn.close()