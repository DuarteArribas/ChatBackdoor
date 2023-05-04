from configparser import ConfigParser
from src.chatClient import *

def main():
  # read configuration from config file
  cfg = ConfigParser("config/clientconf.cfg")
  client = ChatClient(
    cfg.get("APP","IP"),
    cfg.get("APP","PORT")
  )
  client.runClient("a",["test.txt","test.txt"])
  
if __name__ == '__main__':
  main()