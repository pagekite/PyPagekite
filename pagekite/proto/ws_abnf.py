"""
websocket - WebSocket client library for Python

Copyright (C) 2010 Hiroki Ohtani(liris)

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor,
    Boston, MA  02110-1335  USA

"""
import array
import os
import struct
import six
from threading import Lock

try:
    if six.PY3:
        import numpy
    else:
        numpy = None
except ImportError:
    numpy = None

try:
    # If wsaccel is available we use compiled routines to mask data.
    if not numpy:
        from wsaccel.xormask import XorMaskerSimple

        def _mask(_m, _d):
            return XorMaskerSimple(_m).process(_d)
except ImportError:
    # wsaccel is not available, we rely on python implementations.
    def _mask(_m, _d):
        for i in range(len(_d)):
            _d[i] ^= _m[i % 4]

        if six.PY3:
            return _d.tobytes()
        else:
            return _d.tostring()


__all__ = [
    'ABNF', 'continuous_frame', 'frame_buffer',
    'STATUS_NORMAL',
    'STATUS_GOING_AWAY',
    'STATUS_PROTOCOL_ERROR',
    'STATUS_UNSUPPORTED_DATA_TYPE',
    'STATUS_STATUS_NOT_AVAILABLE',
    'STATUS_ABNORMAL_CLOSED',
    'STATUS_INVALID_PAYLOAD',
    'STATUS_POLICY_VIOLATION',
    'STATUS_MESSAGE_TOO_BIG',
    'STATUS_INVALID_EXTENSION',
    'STATUS_UNEXPECTED_CONDITION',
    'STATUS_BAD_GATEWAY',
    'STATUS_TLS_HANDSHAKE_ERROR',
    'WebSocketException',
    'WebSocketProtocolException'
]

# closing frame status codes.
STATUS_NORMAL = 1000
STATUS_GOING_AWAY = 1001
STATUS_PROTOCOL_ERROR = 1002
STATUS_UNSUPPORTED_DATA_TYPE = 1003
STATUS_STATUS_NOT_AVAILABLE = 1005
STATUS_ABNORMAL_CLOSED = 1006
STATUS_INVALID_PAYLOAD = 1007
STATUS_POLICY_VIOLATION = 1008
STATUS_MESSAGE_TOO_BIG = 1009
STATUS_INVALID_EXTENSION = 1010
STATUS_UNEXPECTED_CONDITION = 1011
STATUS_BAD_GATEWAY = 1014
STATUS_TLS_HANDSHAKE_ERROR = 1015

# A mask that does nothing
ZERO_MASK = "\0\0\0\0"

VALID_CLOSE_STATUS = (
    STATUS_NORMAL,
    STATUS_GOING_AWAY,
    STATUS_PROTOCOL_ERROR,
    STATUS_UNSUPPORTED_DATA_TYPE,
    STATUS_INVALID_PAYLOAD,
    STATUS_POLICY_VIOLATION,
    STATUS_MESSAGE_TOO_BIG,
    STATUS_INVALID_EXTENSION,
    STATUS_UNEXPECTED_CONDITION,
    STATUS_BAD_GATEWAY,
)


class WebSocketNeedMoreDataException(Exception):
    pass


class WebSocketException(IOError):
    pass


class WebSocketProtocolException(WebSocketException):
    pass


class ABNF(object):
    """
    ABNF frame class.
    see http://tools.ietf.org/html/rfc5234
    and http://tools.ietf.org/html/rfc6455#section-5.2
    """

    # operation code values.
    OPCODE_CONT = 0x0
    OPCODE_TEXT = 0x1
    OPCODE_BINARY = 0x2
    OPCODE_CLOSE = 0x8
    OPCODE_PING = 0x9
    OPCODE_PONG = 0xa

    # available operation code value tuple
    OPCODES = (OPCODE_CONT, OPCODE_TEXT, OPCODE_BINARY, OPCODE_CLOSE,
               OPCODE_PING, OPCODE_PONG)

    # opcode human readable string
    OPCODE_MAP = {
        OPCODE_CONT: "cont",
        OPCODE_TEXT: "text",
        OPCODE_BINARY: "binary",
        OPCODE_CLOSE: "close",
        OPCODE_PING: "ping",
        OPCODE_PONG: "pong"
    }

    # data length threshold.
    LENGTH_7 = 0x7e
    LENGTH_16 = 1 << 16
    LENGTH_63 = 1 << 63

    def __init__(self, fin=0, rsv1=0, rsv2=0, rsv3=0,
                 opcode=OPCODE_TEXT, mask=1, data="", zero_mask=False):
        """
        Constructor for ABNF.
        please check RFC for arguments.
        """
        self.fin = fin
        self.rsv1 = rsv1
        self.rsv2 = rsv2
        self.rsv3 = rsv3
        self.opcode = opcode
        self.mask = mask
        self.data = data or ""
        self.length = len(self.data)
        if zero_mask:
            self.get_mask_key = lambda c: ZERO_MASK
        else:
            self.get_mask_key = os.urandom

    def validate(self):
        """
        validate the ABNF frame.
        """
        if self.rsv1 or self.rsv2 or self.rsv3:
            raise WebSocketProtocolException("rsv is not implemented, yet")

        if self.opcode not in ABNF.OPCODES:
            raise WebSocketProtocolException("Invalid opcode %r", self.opcode)

        if self.opcode == ABNF.OPCODE_PING and not self.fin:
            raise WebSocketProtocolException("Invalid ping frame.")

        if self.opcode == ABNF.OPCODE_CLOSE:
            l = len(self.data)
            if not l:
                return
            if l == 1 or l >= 126:
                raise WebSocketProtocolException("Invalid close frame.")

            code = 256 * \
                six.byte2int(self.data[0:1]) + six.byte2int(self.data[1:2])
            if not self._is_valid_close_status(code):
                raise WebSocketProtocolException("Invalid close opcode.")

    @staticmethod
    def _is_valid_close_status(code):
        return code in VALID_CLOSE_STATUS or (3000 <= code < 5000)

    def __str__(self):
        return "fin=" + str(self.fin) \
            + " opcode=" + str(self.opcode) \
            + " data=" + str(self.data)

    @staticmethod
    def create_frame(data, opcode, fin=1, zero_mask=False):
        """
        create frame to send text, binary and other data.

        data: data to send. This is string value(byte array).
            if opcode is OPCODE_TEXT and this value is unicode,
            data value is converted into unicode string, automatically.

        opcode: operation code. please see OPCODE_XXX.

        fin: fin flag. if set to 0, create continue fragmentation.
        """
        if opcode == ABNF.OPCODE_TEXT and isinstance(data, six.text_type):
            data = data.encode("utf-8")
        # mask must be set if send data from client
        return ABNF(fin, 0, 0, 0, opcode, 1, data, zero_mask)

    def format(self):
        """
        format this object to string(byte array) to send data to server.
        """
        if any(x not in (0, 1) for x in [self.fin, self.rsv1, self.rsv2, self.rsv3]):
            raise ValueError("not 0 or 1")
        if self.opcode not in ABNF.OPCODES:
            raise ValueError("Invalid OPCODE")
        length = len(self.data)
        if length >= ABNF.LENGTH_63:
            raise ValueError("data is too long")

        frame_header = chr(self.fin << 7
                           | self.rsv1 << 6 | self.rsv2 << 5 | self.rsv3 << 4
                           | self.opcode)
        if length < ABNF.LENGTH_7:
            frame_header += chr(self.mask << 7 | length)
            frame_header = six.b(frame_header)
        elif length < ABNF.LENGTH_16:
            frame_header += chr(self.mask << 7 | 0x7e)
            frame_header = six.b(frame_header)
            frame_header += six.b(struct.pack("!H", length))
        else:
            frame_header += chr(self.mask << 7 | 0x7f)
            frame_header = six.b(frame_header)
            frame_header += six.b(struct.pack("!Q", length))

        if not self.mask:
            return frame_header + self.data
        else:
            mask_key = self.get_mask_key(4)
            return frame_header + mask_key + ABNF.mask(mask_key, self.data)

    @staticmethod
    def mask(mask_key, data):
        """
        mask or unmask data. Just do xor for each byte

        mask_key: 4 byte string(byte).

        data: data to mask/unmask.
        """
        if data is None:
            data = ""

        if mask_key == ZERO_MASK:
            return data

        if isinstance(mask_key, six.text_type):
            mask_key = six.b(mask_key)

        if isinstance(data, six.text_type):
            data = six.b(data)

        if len(data) < 1:
            return data

        if numpy:
            origlen = len(data)
            _mask_key = mask_key[3] << 24 | mask_key[2] << 16 | mask_key[1] << 8 | mask_key[0]

            # We need data to be a multiple of four...
            data += bytes(" " * (4 - (len(data) % 4)), "us-ascii")
            a = numpy.frombuffer(data, dtype="uint32")
            masked = numpy.bitwise_xor(a, [_mask_key]).astype("uint32")
            if len(data) > origlen:
              return masked.tobytes()[:origlen]
            return masked.tobytes()
        else:
            _m = array.array("B", mask_key)
            _d = array.array("B", data)
            return _mask(_m, _d)

    def parse_header(self, data):
        try:
            b1 = data[0]
            b2 = data[1]
        except IndexError:
            raise WebSocketNeedMoreDataException()

        if six.PY2:
            b1 = ord(b1)
            b2 = ord(b2)

        self.fin = b1 >> 7 & 1
        self.rsv1 = b1 >> 6 & 1
        self.rsv2 = b1 >> 5 & 1
        self.rsv3 = b1 >> 4 & 1
        self.opcode = b1 & 0xf

        has_mask = b2 >> 7 & 1
        length_bits = b2 & 0x7f

        return has_mask, length_bits, data[2:]

    def parse_length(self, length_bits, data):
        if length_bits == 0x7e:
            if len(data) < 2:
                raise WebSocketNeedMoreDataException()
            self.length = struct.unpack("!H", b(data[:2]))[0]
            return data[2:]
        elif length_bits == 0x7f:
            if len(data) < 8:
                raise WebSocketNeedMoreDataException()
            self.length = struct.unpack("!Q", b(data[:8]))[0]
            return data[8:]
        else:
            self.length = length_bits
            return data

    def parse_mask(self, has_mask, data):
        if has_mask:
            if len(data) < 4:
                raise WebSocketNeedMoreDataException()
            self.mask = data[:4]
            return data[4:]
        else:
            self.mask = ""
            return data

    def parse_data(self, data):
        payload = data[:self.length]
        if len(payload) == self.length:
            self.data = ABNF.mask(self.mask, payload)
            self.validate()
        return data[self.length:]

    @classmethod
    def parse(cls, all_data):
        self = cls()
        try:
            has_mask, length_bits, data = self.parse_header(all_data)
            data = self.parse_length(length_bits, data)
            data = self.parse_mask(has_mask, data)
            data = self.parse_data(data)
            return self, data
        except WebSocketNeedMoreDataException:
            return None, ""
