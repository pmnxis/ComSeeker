import os
import serial
import serial.rs485
import struct
import time
import datetime
import Queue
from enum import Enum
from threading import Thread

lcd_print0 =    b"\x28\x02\x10\xf1\x64"
lcd_print1 =    b"\x28\x02\x10\x64\xff\xff\x3b\x5c"
lcd_print2 =    b"\x29\x03\xa1\x00\x00\x00\x00\x1e\x28"
lcd_print3 =    b"\x28\x03\x91\x64\x00\x00\x00\xa3\x06\x01\x00\x00\x00\x01\x1f\x00\x00\x00\x00\x00\x00\x10\x00\x10\x00\x00\x00\x01\x00\x02\x00\x00\x00\x01\x01\x01\x00\x00\x00\x04\x00\x00\x00\x20\x20\x20\x20\x68\x30"
lcd_test =      b"\x28\x03\x91\x64\x00\x00\x00\xA3\x06\x01\x00\x00\x00\x01\x3D\x00\x00\x00\x00\x03\x00\x08\x00\x09\x00\x00\x00\x00\x00\x02\x00\x00\x00\x01\x01\x03\x00\x0D\x00\x22\x00\x00\x00\x5C\x46\x45\x30\x30\x32\x74\x68\x69\x73\x20\x69\x73\x20\x74\x65\x73\x74\x20\x6D\x65\x73\x73\x61\x67\x65\x20\x68\x65\x79\x20\x61\x20\x20\xF7\x57\x28\x03\x5F\xB1"

#if __name__ == "__main__"

class pkt_start(Enum):
    dev_all = 0,
    dev1 = 1,
    dev2 = 2,
    dev3 = 3,
    dev4 = 4,
    dev5 = 5,
    dev6 = 6,
    dev7 = 7,
    dev8 = 8,
    dev9 = 9,
    dev10 = 10,
    dev11 = 11,
    dev12 = 12,
    dev13 = 13,
    dev14 = 14,
    dev15 = 15,
    dev16 = 16,
    dev_lcd = 28,
    dev_lcd_r = 29

class pkt_src(Enum):
    Unknown = 0,
    RX = 1,
    TX = 2


class interprerter:
    self.pkt_src_str = [
        'Unknown',
        'RX',
        'TX'
    ]
    self.pkt_description_table = [
        'new packet',
        'duplicated to'
    ]

    def gen_description(dup_code, prev_code):
        if dup_code is -1:
            return self.pkt_description_table[0]
        if dup_code >= 0:
            temp = '%s N -% d' % self.pkt_description_table[1], prev_code
            return temp
    
    def gen_ev_str(dup_code, prev_code, hex_arr):
        if dup_code is -1:
            return '[!]'
        if dup_code >= 0:
            return '[+]'
    
# todo : csv write order is strange curently, need to fix asap.


class log_engine(Thread):
    def __init__(self, filename = self.gen_logname(), duplicate_kill = 2, echo = True):
        if not os.path.exists('log'):
            os.makedirs('log')
        temp = './log/'
        temp += filename
        self.file = open(filename, 'w')
        self.file.write(filename)
        self.file.write('\n')
        self.file.write('Ev,Len,Time Gap,Description,hex,ASCII')
        self.__lock = False
        self.__exit = False
        self.echo_enable = False
        self.queue = queue.Queue()
        # dup_list should contain hex->str lized string
        self.dup_list = []
        self.dup_val = duplicate_kill
        if echo == True:
            self.echo_enable = True
        Thread.__init__(self)

    def run(self):
        while True:
            if self.__lock == False:
                if self.queue.empty() == False:
                    self.prog()
            if self.__exit == True:
                break

    def exit(self):
        t = -1
        for i in range (0, 100):
            if self.queue.empty() == False:
                time.sleep(0.1)
            else:
                t = 0
        if t is -1:
            print("log_engine is busy")
            self.__exit = True


    def prog(self):
        if self.queue.empty() == False:
            return
        temp = self.queue.get()
        temp_hex = "".join("%02x " % b for b in temp[3])
        dup = int(-1)
        # for count n - 1 blahblah
        dup_sub = int(0)
        for a in reversed range (0, self.dup_val):
            dup_sub += 1
            if len(self.dup_list) >= a:
                continue
            if (self.dup_list[a] == temp_hex):
                dup = a
                break
        if (len(self.dup_list) >= self.dup_val):
            del (self.dup_list[0])
        self.dup_list.append(temp_hex)
        temp_desc = interprerter.gen_description(dup, dup_sub)
        temp_ev = interprerter.gen_ev_str(dup,dup_sub, False)
        log_write(temp_ev, temp[1] ,temp_desc, temp[3])
        log_echo(temp_ev, temp[1] ,temp_desc, temp[3])

    def call(self, ev, desc, timegap, hex_bytes):
        while self.__lock == True:
            print("log_engine lock issue")
        # this should be fix to mutex
        self.__lock = True:
        temp = []
        temp.append(ev)
        temp.append(timegap)
        temp.append(desc)
        temp.append(hex_bytes)
        self.queue.put(temp)
        self.__lock = False:

    def log_write (self, ev, timegap, desc, hex_bytes):
        temp = str()
        size = len(hex_bytes)
        temp_size = '%d(% 2x)' % size, size
        temp_ascii = "".join("%c" % b for b in hex_bytes)
        temp_hex = "".join("%02x " % b for b in hex_bytes)
        temp = '%s,%s,%d,%s,%s\n' % ev, temp_size ,timegap, desc, temp_hex, temp_ascii 
        self.file.write(temp)

    def log_echo (self, ev, timegap, desc, hex_bytes):
        size = len(hex_bytes)
        # 3+3+5+24+6+2 = 43
        temp_front = '% 3s% 3dBytes% 24s% 6dms' % ev, size
        t = size//16
        k = size%16
        if k > 0:
            t += 1
        temp = ''
        blank = ' '
        for in i range (0, t):
            if (i+1)*16 <= size:
                d = 16
            else:
                d = (size-(i*16))

            temp_ascii  = "".join(chr(b) for b in hex_bytes[i*16:i*16+d])
            temp_hex    = "".join(" %02x" % b for b in hex_bytes[i*16:i*16+d])
            # need to fill padding reversely. need to fix later.
            if i is 0:
                temp = '% 43s % 24s % 8s\n' % temp_front, temp_hex, temp_ascii
            else:
                temp = temp + '% 43s % 24s % 8s\n' % blank, temp_hex, temp_ascii
        print(temp, end='')

    def gen_logname(self, prefix = "dump+", endfix = ".csv"):
        temp = str()
        temp += prefix
        now = datetime.datetime.now()
        temp += now.strftime("%Y-%m-%d-%H-%M")
        temp += endfix
        return temp

    def __del__(self):
        file.close()


class app(Thread):
    def __init__(self, port_path, hw485io = False, analyze_log = False, print_log = False):
        self.ser = serial.Serial(
            port=port_path,
            baudrate=115200,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            bytesize=serial.EIGHTBITS,
            timeout=0.001
        )

        self.policy_rtscts = False
        self.policy_logger = False
        self.policy_printout = False
        self.dt = getmstime()
        if hw485io is True:
            self.policy_logger = True
            self.enable_native_rs485_io()

        if analyze_log is True:
            self.policy_logger = True
            if print_log is True:
                self.policy_printout = True
            # log_engine should be run with thread tech
            # referenced way to do article by https://bbolmin.tistory.com/164
            self.logger = log_engine(duplicate_kill=2, echo = print_log)
            self.logger.start()
            print("log_engine enabled")
            time.sleep(0.1)
    
    def __del__(self):
        self.ser.close()
        self.log.close()

    def enable_native_rs485_io(self):
        i = int(0)
        while i < 1:
            try:
                self.ser.rs485_mode = serial.rs485.RS485Settings(False,True)
                print('rs485 mode is accepcpted by ioctl')
                return 1
            except ValueError:
                pass
                self.ser.rs485_mode = False
                print('rs485 mode is denied by ioctl or unknown issue. - ValueError')
                return -1
            except Exception:
                pass
                self.ser.rs485_mode = False
                print('rs485 mode is denied by ioctl or unknown issue. - Exception')
                return -2

    def read_packet(self):
        temp = []
        while 1:
            ch = self.ser.read()
            if len(ch) == 0:
                break
            temp += ch
        return temp

    def basic_work(self)
        a = program.read_packet()
        if len(a) != 0:
                dy = getmstime()
                __timegap = dy-self.dt
                if self.policy_logger == True:
                    self.logger.call(ev=0, desc=0, timegap=__timegap, )
                self.dt = dy


    def run(self, packet):
        if self.policy_logger == True:
            self.logger.call(ev=0, desc=0, )
        
def getmstime():
    return int(round(time.time() * 1000))



def main():
    program = app('/dev/ttyS1')
    dt = getmstime()
    hex_string = str('_______')
# this function for logging data
    

    while 1:
        
        a = program.read_packet()
        if len(a) != 0:
            hex_string_bak = hex_string
            hex_string = "".join(" %02x" % b for b in a)
            if (hex_string != hex_string_bak):
                dy = getmstime()
                print('[+]% 6d ms Gap : ' % (dy - dt), end='')
                dt = dy
                print(hex_string)
            else:
                dy = getmstime()
                print('[#]% 6d ms after repeat : ' % (dy - dt), end='\n')
                dt = dy
                
            

main()

'''
# ser.open()
#ser.write(lcd_print0)
time.sleep(0.007)
#ser.write(lcd_print1)
time.sleep(0.340)
ser.write(lcd_print2)
time.sleep(0.9)
ser.write(lcd_print3)
time.sleep(0.1)
ser.write(lcd_test)
ser.close()
'''