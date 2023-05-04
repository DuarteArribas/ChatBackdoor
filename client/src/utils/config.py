import configparser

class Config:
  """A config tool, which reads from the given configuration file."""
  
  # == Methods ==
  def __init__(self,configFile):
    """Set the default configuration of the config reading tool.
    
    Parameters
    ----------
    configFile : str
      The configuration file to read from
    """
    self.config = configparser.RawConfigParser()
    configList  = self.config.read(configFile)
    if len(configList) == 0:
      print("Could not read config file. Exiting...")
      exit(-1)

  def getAppConfig(self,key):
    """Get a config from the APP section on the config file.
    
    Parameters
    ----------
    key : str
      The key corresponding to the wanted configuration
      
    Returns
    ----------
    str
      The corresponding configuration
    """
    return self.config.get("APP",key)
  
  def getLogsConfig(self,key):
    """Get a config from the LOGS section on the config file.
    
    Parameters
    ----------
    key : str
      The key corresponding to the wanted configuration
      
    Returns
    ----------
    str
      The corresponding configuration
    """
    return self.config.get("LOGS",key)
  
  def getEmailConfig(self,key):
    """Get a config from the EMAIL section on the config file.
    
    Parameters
    ----------
    key : str
      The key corresponding to the wanted configuration
      
    Returns
    ----------
    str
      The corresponding configuration
    """
    return self.config.get("EMAIL",key)
  
  def getValidationConfig(self,key):
    """Get a config from the VALIDATION section on the config file.
    
    Parameters
    ----------
    key : str
      The key corresponding to the wanted configuration
      
    Returns
    ----------
    str
      The corresponding configuration
    """
    return self.config.get("VALIDATION",key)
  
  def getEPOSDBConfig(self,key):
    """Get a config from the EPOSDB section on the config file.
    
    Parameters
    ----------
    key : str
      The key corresponding to the wanted configuration
      
    Returns
    ----------
    str
      The corresponding configuration
    """
    return self.config.get("EPOSDB",key)
  
  def getUploadConfig(self,key):
    """Get a config from the UPLOAD section on the config file.
    
    Parameters
    ----------
    key : str
      The key corresponding to the wanted configuration
      
    Returns
    ----------
    str
      The corresponding configuration
    """
    return self.config.get("UPLOAD",key)