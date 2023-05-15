class Menu():
  INITIAL_MENU_OPTIONS = [0,1,2]
  
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