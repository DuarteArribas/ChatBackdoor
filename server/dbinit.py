import sqlite3
import sys
from configparser import ConfigParser

CONFIG_FILE = "server/config/serverconf.cfg"

def main():
  # Read config file
  cfg = ConfigParser()
  cfg.read(CONFIG_FILE)
  # Get a connection to the local database and cursor
  con = sqlite3.connect(cfg.get("APP","LOCAL_DATABASE_FILE"))
  cur = con.cursor()
  # Create table
  try:
    cur.execute("CREATE TABLE users(username VARCHAR PRIMARY KEY,password VARCHAR, dA TEXT,temp INTEGER,chapNonce TEXT)")
    cur.execute("CREATE TABLE friends(username1 VARCHAR, username2 VARCHAR,acceptance INTEGER,PRIMARY KEY(username1,username2))")
    cur.execute("CREATE TABLE messages(ID INTEGER PRIMARY KEY AUTOINCREMENT,username1 VARCHAR, username2 VARCHAR,message TEXT")
    con.commit()
    print("Database created successfully!")
  except sqlite3.OperationalError:
    con.rollback()
    print("Database already exists. Did nothing...",file = sys.stderr)

if __name__ == '__main__':
  main()