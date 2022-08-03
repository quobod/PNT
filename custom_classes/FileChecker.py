from custom_modules import (
    PatternConstants as pattern,
    ArgumentManager as arguments,
    PlatformConstants as platform,
    Utils as utils,
    FileValidator as file_validator,
)
from custom_modules.ConsoleMessenger import CONSOLE_MESSENGER_SWITCH as cms
from custom_classes.FileInterrorgator import file_interrogator as fi


class FileChecker:
    __COMMAND_SWITCH = {
        "exists": file_validator.exists,
        "is_file": file_validator.is_file,
        "is_dir": file_validator.is_dir,
        "is_sym_link": file_validator.is_symLink,
        "has_ext": file_validator.has_extension,
        "has_extension": file_validator.has_extension,
    }

    def __init__(self) -> None:
        pass

    def check_file(self, command, file_path):
        if not pattern.alphabet_pattern.search(command) == None:
            try:
                action = self.__COMMAND_SWITCH[command]
                results = action(file_path)

                if not results == None:
                    if not results == False:
                        xm = cms["success"]
                        msg = "Command [{}]\nPath: {}\nResults: {}\n".format(
                            command, file_path, results
                        )
                        utils.log("{}".format(xm(msg)))
                    else:
                        wm = cms["warning"]
                        msg = "Command [{}]\nPath: {}\nResults: {}".format(
                            command, file_path, results
                        )
                        wmsg = wm(msg)
                        utils.log(wmsg)

            except TypeError as te:
                wm = cms["warning"]
                msg = "Command [{}] is not available".format(te)
                wmsg = wm(msg)
                utils.log(wmsg)

            except KeyError as ke:
                wm = cms["warning"]
                msg = "Command [{}] is not available".format(ke)
                wmsg = wm(msg)
                utils.log(wmsg)
        else:
            em = cms["error"]
            msg = "Command [{}] must contain only alphabet characters, including an inderscore".format(
                command
            )
            emsg = em(msg)
            utils.log(emsg)


file_checker = FileChecker
