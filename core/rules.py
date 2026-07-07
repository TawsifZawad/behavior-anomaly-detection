import re


SUSPICIOUS_POWERSHELL_KEYWORDS = {

    "-enc",
    "-encodedcommand",

    "invoke-expression",
    "iex",

    "downloadstring",
    "downloadfile",

    "invoke-webrequest",
    "iwr",

    "curl",
    "wget",

    "net.webclient",

    "frombase64string",

    "bypass",
    "hidden",
    "nop",

    "invoke-mimikatz"

}


def powershell_rule(commandline):

    if not commandline:
        return False

    cmd = commandline.lower()

    for keyword in SUSPICIOUS_POWERSHELL_KEYWORDS:

        if keyword in cmd:
            return True

    return False