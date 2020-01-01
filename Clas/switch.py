"""Support for Clas Ohlson devices."""
import binascii
from datetime import timedelta
import logging
import socket

from . import clas as _clas
import voluptuous as vol

from homeassistant.components.switch import (
    ENTITY_ID_FORMAT,
    PLATFORM_SCHEMA,
    SwitchDevice,
)
from homeassistant.const import (
    CONF_COMMAND_OFF,
    CONF_COMMAND_ON,
    CONF_FRIENDLY_NAME,
    CONF_HOST,
    CONF_MAC,
    CONF_SWITCHES,
    CONF_TIMEOUT,
    CONF_TYPE,
    STATE_ON,
)
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.restore_state import RestoreEntity
from homeassistant.util import Throttle, slugify

from . import async_setup_service, data_packet

_LOGGER = logging.getLogger(__name__)

TIME_BETWEEN_UPDATES = timedelta(seconds=5)

DEFAULT_NAME = "Clas switch"
DEFAULT_TIMEOUT = 10
DEFAULT_RETRY = 2
CONF_SLOTS = "slots"
CONF_RETRY = "retry"

SP2_TYPES = ["sp2", "honeywell_sp2", "sp3", "spmini2", "spminiplus"]
SP4_TYPES = ["sp4"]

SWITCH_TYPES = SP4_TYPES + SP2_TYPES

SWITCH_SCHEMA = vol.Schema(
    {
        vol.Optional(CONF_COMMAND_OFF): data_packet,
        vol.Optional(CONF_COMMAND_ON): data_packet,
        vol.Optional(CONF_FRIENDLY_NAME): cv.string,
    }
)

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(
    {
        vol.Optional(CONF_SWITCHES, default={}): cv.schema_with_slug_keys(
            SWITCH_SCHEMA
        ),
        vol.Required(CONF_HOST): cv.string,
        vol.Required(CONF_MAC): cv.string,
        vol.Optional(CONF_FRIENDLY_NAME, default=DEFAULT_NAME): cv.string,
        vol.Optional(CONF_TYPE, default=SWITCH_TYPES[0]): vol.In(SWITCH_TYPES),
        vol.Optional(CONF_TIMEOUT, default=DEFAULT_TIMEOUT): cv.positive_int,
        vol.Optional(CONF_RETRY, default=DEFAULT_RETRY): cv.positive_int,
    }
)


def setup_platform(hass, config, add_entities, discovery_info=None):
    """Set up the Clas Ohlson switches."""

    devices = config.get(CONF_SWITCHES)
    slots = config.get("slots", {})
    ip_addr = config.get(CONF_HOST)
    friendly_name = config.get(CONF_FRIENDLY_NAME)
    mac_addr = binascii.unhexlify(config.get(CONF_MAC).encode().replace(b":", b""))
    switch_type = config.get(CONF_TYPE)
    retry_times = config.get(CONF_RETRY)

    def _get_mp1_slot_name(switch_friendly_name, slot):
        """Get slot name."""
        if not slots[f"slot_{slot}"]:
            return f"{switch_friendly_name} slot {slot}"
        return slots[f"slot_{slot}"]

    if switch_type in SP4_TYPES:
        clas_device = _clas.sp4((ip_addr, 80), mac_addr, 0x7579, None)
        switches = [ClasSP4(friendly_name, clas_device, retry_times)]
    
    elif switch_type in SP2_TYPES:
        clas_device = _clas.sp2((ip_addr, 80), mac_addr, None)
        switches = [ClasSP2(friendly_name, clas_device, retry_times)]
        
    clas_device.timeout = config.get(CONF_TIMEOUT)
    try:
        clas_device.auth()
    except OSError:
        _LOGGER.error("Failed to connect to device")

    add_entities(switches)

class ClasSP4(SwitchDevice):
    """Representation of an Clas Ohlson switch."""
    def __init__(self, name, device, haskey = 0):
        """Initialize the switch."""
        self._haskey = haskey
        
        self.entity_id = ENTITY_ID_FORMAT.format(name)
        self._name = name
        self._dev = device
        self._unique_id = 'sp4' + self._dev.mac.hex()
        #set to true if we failed to set state
        self._update_state = 0
        self._safe_state = {'pwr':0, 'ntlight': 0, 'indicator':0, 'ntlbrightness':60}
        self._state = self._safe_state
        self._is_available = True
        _LOGGER.info("Init done")
        
    @property
    def unique_id(self):
        """Return a unique ID."""
        return self._unique_id
    @property
    def name(self):
        """Return the name of the switch."""
        _LOGGER.info("Name called")
        return self._name

    @property
    def assumed_state(self):
        """Return true if unable to access real state of entity."""
        _LOGGER.info("assumed_state called")
        return False

    @property
    def available(self):
        """Return True if entity is available."""
        _LOGGER.info("available called")
        return True

    @property
    def should_poll(self):
        """Return the polling state."""
        _LOGGER.info("should_poll called")
        return True

    @property
    def is_on(self):
        """Return true if device is on."""
        _LOGGER.info("is_on called")
        try:
            # TODO: write code...
            return self._state['pwr']
        except:
            self._state = self._safe_state #Bad state, update to default state
            return self._state['pwr']
        
    @property
    def device_state_attributes(self):
        """Show state attributes in HASS"""
        _LOGGER.info("device_state_attributes called")
        attrs = {'ip_address': self._dev.host,
                 'mac': self._dev.mac.hex(),
                 'devtype': hex(self._dev.devtype),
                 'type': self._dev.type,
                 'timeout': self._dev.timeout,
                 'haskey': self._haskey
                 }
        
        attrs.update(self._state)
        return attrs

    def turn_on(self, **kwargs):
        """Turn the device on."""
        _LOGGER.info("turn_on called")
        try:
            self._state = self._dev.set_state(pwr=1)
        except:
            self._update_state = {'pwr': 1}
            _LOGGER.error("Except in turn_on")
        return

    def turn_off(self, **kwargs):
        """Turn the device off."""
        _LOGGER.info("turn_off called")
        try:
            self._state = self._dev.set_state(pwr=0)
        except:
            self._update_state = {'pwr': 0}
            _LOGGER.error("Except in turn_off")
        return
    
    def update(self):
        """Synchronize state with switch."""    #Add parsing of all states
        _LOGGER.info("update called")
        if(not self._haskey):
            try:
                if(self._dev.auth()):
                    _LOGGER.info("late auth in update OK")
                    self.haskey = 1
                else:
                    _LOGGER.info("late auth in update FAIL")
            except:
                _LOGGER.error("except in update late auth!!!!!")
        try:
            
            if(self._update_state):
                self._state = self._dev.set_state_dict(self._update_state)
                self._update_state = 0
            else:
                self._state = self._dev.get_state()
        except:
            _LOGGER.error("except in update")

class ClasSP2(_clas.device):
    def __init__(self, host, mac, devtype):
        _clas.device.__init__(self, host, mac, devtype)
        self.type = "SP2"

    def set_power(self, state):
        """Sets the power state of the smart plug."""
        packet = bytearray(16)
        packet[0] = 2
        if self.check_nightlight():
            packet[4] = 3 if state else 2
        else:
            packet[4] = 1 if state else 0
        self.send_packet(0x6a, packet)

    def set_nightlight(self, state):
        """Sets the night light state of the smart plug"""
        packet = bytearray(16)
        packet[0] = 2
        if self.check_power():
            packet[4] = 3 if state else 1
        else:
            packet[4] = 2 if state else 0
        self.send_packet(0x6a, packet)

    def check_power(self):
        """Returns the power state of the smart plug."""
        packet = bytearray(16)
        packet[0] = 1
        response = self.send_packet(0x6a, packet)
        err = response[0x22] | (response[0x23] << 8)
        if err != 0:
            return None
        payload = self.decrypt(bytes(response[0x38:]))
        if isinstance(payload[0x4], int):
            return bool(payload[0x4] == 1 or payload[0x4] == 3 or payload[0x4] == 0xFD)
        return bool(ord(payload[0x4]) == 1 or ord(payload[0x4]) == 3 or ord(payload[0x4]) == 0xFD)

    def check_nightlight(self):
        """Returns the power state of the smart plug."""
        packet = bytearray(16)
        packet[0] = 1
        response = self.send_packet(0x6a, packet)
        err = response[0x22] | (response[0x23] << 8)
        if err != 0:
            return None
        payload = self.decrypt(bytes(response[0x38:]))
        if isinstance(payload[0x4], int):
            return bool(payload[0x4] == 2 or payload[0x4] == 3 or payload[0x4] == 0xFF)
        return bool(ord(payload[0x4]) == 2 or ord(payload[0x4]) == 3 or ord(payload[0x4]) == 0xFF)

    def get_energy(self):
        packet = bytearray([8, 0, 254, 1, 5, 1, 0, 0, 0, 45])
        response = self.send_packet(0x6a, packet)
        err = response[0x22] | (response[0x23] << 8)
        if err != 0:
            return None
        payload = self.decrypt(bytes(response[0x38:]))
        if isinstance(payload[0x7], int):
            energy = int(hex(payload[0x07] * 256 + payload[0x06])[2:]) + int(hex(payload[0x05])[2:]) / 100.0
        else:
            energy = int(hex(ord(payload[0x07]) * 256 + ord(payload[0x06]))[2:]) + int(
                hex(ord(payload[0x05]))[2:]) / 100.0
        return energy
