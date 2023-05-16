from enum import Enum

class Menu():
  """Implements the menus."""
  
  """
  Attributes
  ----------
  MENUS : Enum
    The three possible menus to have
  INITIAL_MENU_OPTIONS : list
    Possible options for the initial menu
      1 for registry
      2 for login
      0 for exit
  MAIN_MENU_OPTIONS    : list
    Possible options for the main menu
      1 for opening the friends' menu
      2 for messaging a friend
      3 for checking messages
      0 for returning to initial menu
  FRIEND_MENU_OPTIONS  : list
    Possible options for the friends' menu
      1 for adding a friend
      2 for checking friends requests
      3 for removing a friend
      4 for checking friends list
      0 for returning to main menu
  """
  # == Attributes ==
  MENUS = Enum('MENUS','INITIAL MAIN FRIEND')
  INITIAL_MENU_OPTIONS = [0,1,2]
  MAIN_MENU_OPTIONS    = [0,1,2,3]
  FRIEND_MENU_OPTIONS  = [0,1,2,3,4]
  
  # == Methods ==
  def __init__(self):
    """Initialize menus."""
    self.currMenu = Menu.MENUS.INITIAL
  
  @staticmethod
  def printInitialMenu():
    print("\n=============================================")
    print("Welcome to the chat! What do you want to do?")
    print("1 - Register")
    print("2 - Login")
    print("0 - Exit")
    print("=============================================")
    
  @staticmethod
  def getInitialMenuOption():
    """Get user's input in the initial menu.

    Return
    ----------
    option : int
      Option chosen by the user
    """
    option = -1
    while True:
      try:
        option = int(input("Option: "))
      except ValueError:
        print(f"Please enter a valid option ({Menu.INITIAL_MENU_OPTIONS[0]}-{Menu.INITIAL_MENU_OPTIONS[-1]})!")
        Menu.printInitialMenu()
        continue
      if option in Menu.INITIAL_MENU_OPTIONS:
        break
      print(f"Please enter a valid option ({Menu.INITIAL_MENU_OPTIONS[0]}-{Menu.INITIAL_MENU_OPTIONS[-1]})!")
      Menu.printInitialMenu()
    return option
  
  @staticmethod
  def printMainMenu():
    print("\n=============================================")
    print("Welcome to your main page! Select an option!")
    print("1 - Friend list")
    print("2 - Message a friend")
    print("3 - Check messages")
    print("0 - Exit")
    print("=============================================")
    
  @staticmethod
  def getMainMenuOption():
    """Get user's input in the main menu.

    Return
    ----------
    option : int
      Option chosen by the user
    """
    option = -1
    while True:
      try:
        option = int(input("Option: "))
      except ValueError:
        print(f"Please enter a valid option ({Menu.MAIN_MENU_OPTIONS[0]}-{Menu.MAIN_MENU_OPTIONS[-1]})!")
        Menu.printMainMenu()
        continue
      if option in Menu.MAIN_MENU_OPTIONS:
        break
      print(f"Please enter a valid option ({Menu.MAIN_MENU_OPTIONS[0]}-{Menu.MAIN_MENU_OPTIONS[-1]})!")
      Menu.printMainMenu()
    return option

  @staticmethod
  def printFriendMenu():
    print("\n=============================================")
    print("Welcome to your friends page! Which friends are you choosing today?")
    print("1 - Add a friend")
    print("2 - Friend requests")
    print("3 - Remove friend")
    print("4 - Check friends list")
    print("0 - Exit")
    print("=============================================")
  
  @staticmethod
  def getFriendMenuOption():
    """Get user's input in the friends menu.

    Return
    ----------
    option : int
      Option chosen by the user
    """
    option = -1
    while True:
      try:
        option = int(input("Option: "))
      except ValueError:
        print(f"Please enter a valid option ({Menu.FRIEND_MENU_OPTIONS[0]}-{Menu.FRIEND_MENU_OPTIONS[-1]})!")
        Menu.printFriendMenu()
        continue
      if option in Menu.FRIEND_MENU_OPTIONS:
        break
      print(f"Please enter a valid option ({Menu.FRIEND_MENU_OPTIONS[0]}-{Menu.FRIEND_MENU_OPTIONS[-1]})!")
      Menu.printFriendMenu()
    return option