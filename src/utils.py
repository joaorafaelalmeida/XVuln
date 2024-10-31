import json
from enum import Enum

from src.constants import *

class msglvl(str, Enum):
    """
    Enum class for message level
    """
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"

def log_message(level, fstr, *args, **kwargs):
    """
    Logging function based on message priority level

    :param message: Message to print
    :param level: Logging level
    :param *args: Positional arguments passed to the string
    :param **kwargs: Keyword arguments passed to the string
    """
    
    msglvl_list = list(msglvl)

    if msglvl_list.index(level) >= msglvl_list.index(MESSAGE_MIN_LEVEL):
        fstr = fstr.format(*args, **kwargs)
        print(f'[TrustVuln] {level}:', fstr, flush=True)

def print_config(config):
    """
    Printing the global configuration in a user friendly way using json indent
    """
    log_message(msglvl.INFO, 'Dumping current configuration')
    print(json.dumps(config, indent=4), flush=True)

def set_message_level(message_level):
    """
    Set message minimum printing level
    """
    global MESSAGE_MIN_LEVEL

    if message_level in msglvl.__members__:
        MESSAGE_MIN_LEVEL = msglvl[message_level].value