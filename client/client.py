from configparser import ConfigParser
from src.chatClient import *
from src.menu import *

def main():
  # read configuration from config file
  cfg = ConfigParser()
  cfg.read("client/config/clientconf.cfg")
  menuHandler = Menu()
  client = ChatClient(
    cfg.get("APP","IP"),
    cfg.get("APP","PORT"),
    menuHandler
  )
  option = -1
  while not (option == 0 and menuHandler.currMenu == Menu.MENUS.INITIAL):
    if menuHandler.currMenu == Menu.MENUS.INITIAL:
      Menu.printInitialMenu()
      option = Menu.getInitialMenuOption()
      client.runClient(option)
    elif menuHandler.currMenu == Menu.MENUS.MAIN:
      Menu.printMainMenu()
      option = Menu.getMainMenuOption()
      client.runClient(option)
      option = -1 if option == 0 else option
    elif menuHandler.currMenu == Menu.MENUS.FRIEND:
      Menu.printFriendMenu()
      option = Menu.getFriendMenuOption()
      client.runClient(option)
      option = -1 if option == 0 else option
  
if __name__ == '__main__':
  main()