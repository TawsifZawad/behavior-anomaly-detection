class WindowsFilter:

    LOGIN_EVENTS = {
        4624,
        4625
    }

    PROCESS_EVENTS = {
        4688
    }

    FILE_EVENTS = {
        4663
    }

    USB_EVENTS = {
        6416
    }

    def allow_login(self, event_id):

        return event_id in self.LOGIN_EVENTS

    def allow_process(self, event_id):

        return event_id in self.PROCESS_EVENTS

    def allow_file(self, event_id):

        return event_id in self.FILE_EVENTS

    def allow_usb(self, event_id):

        return event_id in self.USB_EVENTS