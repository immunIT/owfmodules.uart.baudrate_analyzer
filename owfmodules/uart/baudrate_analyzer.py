# Octowire Framework
# Copyright (c) ImmunIT - Jordan Ovrè / Paul Duncan
# License: Apache 2.0
# Paul Duncan / Eresse <pduncan@immunit.ch>
# Jordan Ovrè / Ghecko <jovre@immunit.ch>

import codecs
import math
import time

from collections import Counter

from octowire_framework.module.AModule import AModule
from octowire.uart import UART
from octowire.gpio import GPIO


class BaudrateAnalyzer(AModule):
    def __init__(self, owf_config):
        super(BaudrateAnalyzer, self).__init__(owf_config)
        self.meta.update({
            'name': 'UART baudrate analyzer',
            'version': '1.0.0',
            'description': 'Show characters received on UART with calculated entropy for different baudrate values.',
            'author': 'Jordan Ovrè / Ghecko <jovre@immunit.ch>, Paul Duncan / Eresse <pduncan@immunit.ch>'
        })
        self.options = {
            "uart_interface": {"Value": "", "Required": True, "Type": "int",
                               "Description": "UART interface (0=UART0 or 1=UART1)", "Default": 0},
            "mode": {"Value": "", "Required": True, "Type": "text",
                     "Description": "Method used to perform baudrate detection - see advanced options for details.\nIn "
                                    "'incremental' mode, the baudrate starts at 'baudrate_min' and is incremented by "
                                    "'baudrate_inc' up to 'baudrate_max'.\nIn the 'list' mode, all values "
                                    "defined in 'baudrate_list' will be tested.\nAcceptable values: 'list' & "
                                    "'incremental'.",
                     "Default": "incremental"},
            "reset_pin": {"Value": "", "Required": False, "Type": "int",
                          "Description": "GPIO used as slave reset. If defined, the module will pulse this GPIO to "
                                         "reset the target. See the 'reset_pol' advanced option to "
                                         "define the polarity.",
                          "Default": ""},
            "trigger": {"Value": "", "Required": True, "Type": "bool",
                        "Description": "When true, send the character(s) defined in 'trigger_char' (see advanced "
                                       "options) if the Octowire does not receive anything from the target.",
                        "Default": False}
        }
        self.advanced_options.update({
            "reset_pol": {"Value": "", "Required": True, "Type": "text",
                          "Description": "The polarity of the reset line to cause a reset on the target. "
                                         "Acceptable values: 'low' (active-low) & 'high'.",
                          "Default": "low"},
            "reset_hold": {"Value": "", "Required": True, "Type": "float",
                           "Description": "Hold time required to perform a target reset (in seconds).",
                           "Default": 0.1},
            "reset_delay": {"Value": "", "Required": True, "Type": "float",
                            "Description": "Time to wait after a target reset.",
                            "Default": 0.5},
            "min_entropy": {"Value": "", "Required": False, "Type": "float",
                            "Description": "Minimal entropy value (float). Only baudrates with an entropy greater than "
                                           "this value will be printed. If unset, print the result for all baudrate "
                                           "values.",
                            "Default": ""},
            "baudrate_min": {"Value": "", "Required": True, "Type": "int",
                             "Description": "Minimum baudrate value. (Incremental mode only)",
                             "Default": 300},
            "baudrate_max": {"Value": "", "Required": True, "Type": "int",
                             "Description": "Maximum baudrate value. (Incremental mode only)",
                             "Default": 115200},
            "baudrate_inc": {"Value": "", "Required": True, "Type": "int",
                             "Description": "The baudrate increment value. (Incremental mode only)",
                             "Default": 300},
            "baudrate_list": {"Value": "", "Required": True, "Type": "text",
                              "Description": "Baudrate values to test (comma separated). (List mode only)",
                              "Default": "9600,19200,38400,57600,115200"},
            "trigger_char": {"Value": "", "Required": True, "Type": "hextobytes",
                             "Description": "Character(s) to send when the 'trigger' options is set to True. "
                                            "Format: raw hex (no leading '0x')",
                             "Default": "0D0A"},
        })
        self.baudrates = [9600, 19200, 38400, 57600, 115200]
        self.uart_instance = None
        self.reset_pin = None
        self.valid_characters = None

    def check_options(self):
        """
        Check the user defined options.
        :return: Bool.
        """
        # If reset_pin is set and reset_pol invalid
        if self.options["reset_pin"]["Value"] != "":
            if self.advanced_options["reset_pol"]["Value"].upper() not in ["LOW", "HIGH"]:
                self.logger.handle("Invalid reset polarity.", self.logger.ERROR)
                return False
            if self.options["reset_pin"]["Value"] not in range(0, 15):
                self.logger.handle("Invalid reset pin.", self.logger.ERROR)
                return False
        # Check the mode
        if self.options["mode"]["Value"].upper() not in ["INCREMENTAL", "LIST"]:
            self.logger.handle("Invalid mode option. Please use 'incremental' or 'list'", self.logger.ERROR)
            return False
        # Check the list if the selected mode is 'list'
        if self.options["mode"]["Value"].upper() == "LIST":
            try:
                baud_list = [b.strip() for b in self.advanced_options["baudrate_list"]["Value"].split(",")]
                if not baud_list:
                    self.logger.handle("Empty or invalid baudrate list.", self.logger.ERROR)
                    return False
            except:
                self.logger.handle("Invalid baudrate list", self.logger.ERROR)
        return True

    def wait_bytes(self):
        """
        Wait until receiving a byte (for 1 seconds) from the target.
        :return: Bool.
        """
        timeout = 1
        timeout_start = time.time()

        while time.time() < timeout_start + timeout:
            in_waiting = self.uart_instance.in_waiting()
            if in_waiting > 0:
                return True
        return False

    def change_baudrate(self, baudrate):
        """
        This function changes the baudrate for the target device.
        :param baudrate: Baudrate value
        :return: Bool.
        """
        try:
            # Empty serial_instance buffer
            self.uart_instance.serial_instance.read(self.uart_instance.serial_instance.in_waiting)
            # Configure UART baudrate
            self.uart_instance.configure(baudrate=baudrate)
            # Empty UART in_waiting buffer
            self.uart_instance.receive(self.uart_instance.in_waiting())
            return True
        except (ValueError, Exception) as err:
            self.logger.handle(err, self.logger.ERROR)
            return False

    def trigger_device(self):
        """
        Send character(s) defined by the "trigger_char" advanced option.
        This method is called when no data was receive during the baudrate detection.
        :return: Nothing.
        """
        self.logger.handle("Triggering the device", self.logger.INFO)
        self.uart_instance.transmit(self.advanced_options["trigger_char"]["Value"])
        time.sleep(0.2)

    @staticmethod
    def bytearray_to_hex_repr(b_buff):
        """
        Convert a bytearray to hex representation (string).
        :param b_buff: Bytearray of received bytes from the UART interface.
        :return: String.
        """
        h_string = ""
        for b in b_buff:
            h_string += f"\\x{codecs.encode(bytes([b]), 'hex').decode()}"
        return h_string

    @staticmethod
    def entropy(b_buff):
        """
        Calculate the entropy of a bytearray.
        :param b_buff: Bytearray of received bytes from the UART interface.
        :return:
        """
        p, lns = Counter(b_buff), float(len(b_buff))
        return -sum(count / lns * math.log(count / lns, 2) for count in p.values())

    def print_result(self, baudrate, b_buff, entropy):
        """
        Print the result for a given baudrate.
        :param baudrate: the current baudrate.
        :param b_buff: Bytearray of received bytes from the UART interface.
        :param entropy: The calculated entropy of the received bytes.
        :return: Nothing.
        """
        self.logger.handle(f"Baudrate value: {baudrate} - Entropy: {entropy:.3f} "
                           f"(Got: {self.bytearray_to_hex_repr(b_buff)})",
                           self.logger.USER_INTERACT)

    def process_baudrate(self, baudrate):
        """
        Change the baudrate and check if bytes received on the RX pin are valid characters.
        10 characters are required to calculate the entropy and identify the correct baudrate value.
        :return: Bool.
        """
        count = 0
        threshold = 10
        received_bytes = bytearray()

        loop = 0
        # Dynamic printing
        progress = self.logger.progress('Reading bytes')
        while count < threshold:
            if self.wait_bytes():
                tmp = self.uart_instance.receive(1)
                # Print character read dynamically (Human readable)
                try:
                    tmp.decode()
                    progress.status(tmp.decode())
                except UnicodeDecodeError:
                    tmp2 = tmp
                    progress.status('0x{}'.format(codecs.encode(tmp2, 'hex').decode()))
                # Increment the counter
                count += 1
                # Add the read bytes to the bytes_received buffer
                received_bytes.extend(tmp)
            # Send the defined trigger characters if trigger is True
            elif self.options["trigger"]["Value"] and loop < 3:
                loop += 1
                self.trigger_device()
                continue
            else:
                progress.stop()
                self.logger.handle("No data received using the following baudrate "
                                   "value: {}...".format(baudrate), self.logger.WARNING)
                return False
        # Calculate the entropy of the received bytes and print the result
        # If min_entropy is set, only print result with an entropy greater or equal than the value set by the user.
        entropy = self.entropy(received_bytes)
        if self.advanced_options["min_entropy"]["Value"] != "":
            if entropy >= self.advanced_options["min_entropy"]["Value"]:
                self.print_result(baudrate, received_bytes, entropy)
        else:
            self.print_result(baudrate, received_bytes, entropy)

    def reset_target(self):
        """
        If the reset_pin option is set, reset the target.
        :return: Nothing
        """
        if self.reset_pin is not None:
            self.logger.handle("Attempting to reset the target..", self.logger.INFO)
            if self.advanced_options["reset_pol"]["Value"].upper() == "LOW":
                self.reset_pin.status = 0
                time.sleep(self.advanced_options["reset_hold"]["Value"])
                self.reset_pin.status = 1
            else:
                self.reset_pin.status = 1
                time.sleep(self.advanced_options["reset_hold"]["Value"])
                self.reset_pin.status = 0
            time.sleep(self.advanced_options["reset_delay"]["Value"])

    def init(self):
        """
        Configure the UART and the reset interface (if defined).
        Create the list of valid characters.
        :return:
        """
        # Set and configure UART interface
        self.uart_instance = UART(serial_instance=self.owf_serial, interface_id=self.options["uart_interface"]["Value"])

        # Ensure reset_pin is clear
        self.reset_pin = None
        # Configure the reset line if defined
        if self.options["reset_pin"]["Value"] != "":
            self.reset_pin = GPIO(serial_instance=self.owf_serial, gpio_pin=self.options["reset_pin"]["Value"])
            self.reset_pin.direction = GPIO.OUTPUT
            if self.advanced_options["reset_pol"]["Value"].upper() == "LOW":
                self.reset_pin.status = 1
            else:
                self.reset_pin.status = 0

    def incremental_mode(self):
        """
        Check for valid baudrates using the incremental mode.
        :return: Nothing.
        """
        for baudrate in range(self.advanced_options["baudrate_min"]["Value"],
                              self.advanced_options["baudrate_max"]["Value"],
                              self.advanced_options["baudrate_inc"]["Value"]):
            if self.change_baudrate(baudrate=baudrate):
                self.reset_target()
                if self.process_baudrate(baudrate=baudrate):
                    # Stop the loop if valid baudrate is found
                    break

    def list_mode(self):
        """
        Check for valid baudrates using the list mode.
        :return: Nothing.
        """
        for baudrate in [int(b.strip()) for b in self.advanced_options["baudrate_list"]["Value"].split(",")]:
            if self.change_baudrate(baudrate=baudrate):
                self.reset_target()
                if self.process_baudrate(baudrate=baudrate):
                    # Stop the loop if valid baudrate is found
                    break

    def run(self):
        """
        Main function.
        Try to detect a valid UART baudrate.
        :return: Nothing.
        """
        # If detect_octowire is True then detect and connect to the Octowire hardware. Else, connect to the Octowire
        # using the parameters that were configured. This sets the self.owf_serial variable if the hardware is found.
        self.connect()
        if not self.owf_serial:
            return
        try:
            if self.check_options():
                self.init()
                self.logger.handle("Starting baudrate detection, turn on your target device now", self.logger.HEADER)
                self.logger.handle("Press Ctrl+C to cancel", self.logger.HEADER)
                if self.options["mode"]["Value"].upper() == "INCREMENTAL":
                    self.incremental_mode()
                elif self.options["mode"]["Value"].upper() == "LIST":
                    self.list_mode()
            else:
                return
        except (Exception, ValueError) as err:
            self.logger.handle(err, self.logger.ERROR)
