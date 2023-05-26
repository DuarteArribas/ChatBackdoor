class OptionArgs:
  """Option and arguments sent between the server and client."""
  def __init__(self,option,args):
    """Initialize OptionArgs.
    
    Parameters
    ----------
    option : int
      The option
    args   : tuple
      The arguments
    """
    self.option = option
    self.args   = args