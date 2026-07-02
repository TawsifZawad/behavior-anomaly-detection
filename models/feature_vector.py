class FeatureVector:

    def __init__(
        self,
        username,
        login_hour,
        logout_hour,
        failed_login,
        file_access,
        process_start,
        usb_insert,
        usb_executable_run
    ):

        self.username = username

        self.login_hour = login_hour

        self.logout_hour = logout_hour

        self.failed_login = failed_login

        self.file_access = file_access

        self.process_start = process_start

        self.usb_insert = usb_insert

        self.usb_executable_run = usb_executable_run

    def to_dict(self):

        return {
            "username": self.username,
            "login_hour": self.login_hour,
            "logout_hour": self.logout_hour,
            "failed_login": self.failed_login,
            "file_access": self.file_access,
            "process_start": self.process_start,
            "usb_insert": self.usb_insert,
            "usb_executable_run": self.usb_executable_run
        }

    def __str__(self):

        return str(self.to_dict())