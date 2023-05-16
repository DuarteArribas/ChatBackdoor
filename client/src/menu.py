class Menu():
  INITIAL_MENU_OPTIONS = [0,1,2]
  MAIN_MENU_OPTIONS    = [0,1,2,3]
  FRIEND_MENU_OPTIONS = [0,1,2,3]
  
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
    print("2 - Friend request")
    print("3 - Remove friend request")
    print("0 - Exit")
    print("=============================================")
  
  @staticmethod
  def getFriendMenuOption():
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