POWERSHELL_SUSPICIOUS_KEYWORDS = {

    "-executionpolicy bypass": 20,

    "-encodedcommand": 50,

    "-enc ": 50,

    "invoke-expression": 40,

    "iex ": 40,

    "downloadstring": 40,

    "downloadfile": 40,

    "invoke-webrequest": 30,

    "start-bitstransfer": 30,

    "curl ": 20,

    "wget ": 20,

    "-windowstyle hidden": 30,

    "-w hidden": 30,

    "-nop": 25,

    "-noprofile": 20,

    "-noninteractive": 20,

    "-noni": 20,

    "frombase64string": 40,

    "invoke-command": 30,

    "new-object net.webclient": 40,

    "system.net.webclient": 40,

    "reflection.assembly": 50,

    "add-mppreference": 60,

    "set-mppreference": 60

}