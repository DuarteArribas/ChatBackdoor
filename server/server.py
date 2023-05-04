import sqlite3
from configparser import ConfigParser
from src.chatServer import *

def main():
  # read configuration from config file
  cfg    = ConfigParser()
  cfg.read("server/config/serverconf.cfg")
  # Get a connection to the local database and cursor
  con = sqlite3.connect(cfg.get("APP","LOCAL_DATABASE_FILE"))
  cur = con.cursor()
  # initialize server
  server = ChatServer(
    cfg.get("APP","IP"),
    cfg.get("APP","PORT"),
    cfg.get("APP","MAX_CLIENTS"),
    con,
    cur
  )
  # run server
  server.runServer()

if __name__ == '__main__':
  main()