import mysql.connector

conn = mysql.connector.connect(
    host="localhost",
    user="securechatuser",    # use the new user
    password="MyStrongPass123",
    database="securechat"
)


cursor = conn.cursor()
cursor.execute("SHOW TABLES;")
for t in cursor:
    print(t)

conn.close()
