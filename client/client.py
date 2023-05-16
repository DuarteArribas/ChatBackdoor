from configparser import ConfigParser
from src.chatClient import *
from src.menu import *
import signal,sys

def main():
  try:
    # read configuration from config file
    cfg = ConfigParser()
    cfg.read("client/config/clientconf.cfg")
    menuHandler = Menu()
    client = ChatClient(
      cfg.get("APP","IP"),
      cfg.get("APP","PORT"),
      cfg.get("APP","PORT2"),
      menuHandler
    )
    option = -1
    # create thread
    threading.Thread(target=client.runKeyClient).start()    
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
  except KeyboardInterrupt as ki:
    if menuHandler.currMenu == Menu.MENUS.MAIN or menuHandler.currMenu == Menu.MENUS.FRIEND:
      menuHandler.currMenu = Menu.MENUS.MAIN
      client.runClient(0)
  except Exception as e:
    if menuHandler.currMenu == Menu.MENUS.MAIN or menuHandler.currMenu == Menu.MENUS.FRIEND:
      menuHandler.currMenu = Menu.MENUS.MAIN
      client.runClient(0)
  
if __name__ == '__main__':
  main()