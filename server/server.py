import sqlite3
import threading
from configparser import ConfigParser
from src.chatServer import *

def main():
  # read configuration from config file
  cfg    = ConfigParser()
  cfg.read("server/config/serverconf.cfg")
  # Get a connection to the local database and cursor
  con = sqlite3.connect(cfg.get("APP","LOCAL_DATABASE_FILE"),check_same_thread = False)
  cur = con.cursor()
  # initialize server
  server = ChatServer(
    cfg.get("APP","IP"),
    cfg.get("APP","PORT"),
    cfg.get("APP","PORT2"),
    cfg.get("APP","MAX_CLIENTS"),
    con,
    cur
  )
  # run server
  thread1 = threading.Thread(target = server.runServer)
  thread2 = threading.Thread(target = server.runKeyServer)
  thread1.start()
  thread2.start()

if __name__ == '__main__':
  main()