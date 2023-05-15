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
    cur.execute("CREATE TABLE users(username VARCHAR PRIMARY KEY,password VARCHAR, dA TEXT,temp INTEGER)")
    con.commit()
    print("Database created successfully!")
  except sqlite3.OperationalError:
    con.rollback()
    print("Database already exists. Did nothing...",file = sys.stderr)

if __name__ == '__main__':
  main()