from configparser import ConfigParser
from src.chatClient import *
from src.menu import *

def main():
  # read configuration from config file
  cfg = ConfigParser()
  cfg.read("client/config/clientconf.cfg")
  client = ChatClient(
    cfg.get("APP","IP"),
    cfg.get("APP","PORT")
  )
  option = -1
  while option != 0:
    Menu.printInitialMenu()
    option = Menu.getInitialMenuOption()
    client.runClient(option)
  
if __name__ == '__main__':
  main()