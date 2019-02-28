import os
import sys
import serial
import serial.rs485
import struct
import time
import datetime
is_py2 = sys.version[0] == '2'
if is_py2:
    import Queue as queue
else:
    import queue as queue
from enum import Enum
from threading import Thread

#if __name__ == "__main__"
        
def getmstime():
    return int(round(time.time() * 1000))

def gen_logname(prefix = "dump+", endfix = ".csv"):
    temp = str()
    temp += prefix
    now = datetime.datetime.now()
    temp += now.strftime("%Y-%m-%d-%H-%M")
    temp += endfix
    return temp

def gen_description(dup_code, prev_code):
    if dup_code is -1:
        return "new packet"
    if dup_code >= 0:
        aaa = 'duplicated to'
        temp = '%s N -% d' % (aaa, prev_code)
        return temp

def gen_ev_str(dup_code, prev_code, hex_arr):
    if dup_code is -1:
        return '[!]'
    if dup_code >= 0:
        return '[+]'

def safe_chr(foo):
    if (0x0 <= foo) and (foo < 0x20):
        return '_'
    elif (0x7F <= foo):
        return '_'
    else:
        return chr(foo)

class analyzer(Thread):
    def __init__(self, filename = gen_logname(), duplicate_kill = 2, echo = True):
        if not os.path.exists('log'):
            os.makedirs('log')
        temp = './log/'
        temp += filename
        self.file = open(temp, 'w')
        self.file.write(filename)
        self.file.write('\n')
        self.file.write('Ev,Len,Time Gap,Description,hex,ASCII')
        self.__lock = False
        self.__exit = False
        self.echo_enable = False
        self.queue = queue.Queue()
        self.monitor_num = 0
        self.monitor_list = []
        self.monitor_names = []
        self.monitor_ready = 0
        # dup_list should contain hex->str lized string
        self.dup_list = []
        self.dup_val = duplicate_kill
        if echo == True:
            self.echo_enable = True
        Thread.__init__(self)

    def run(self):
        print('analyzer entered to state run')
        for i in range (0,self.monitor_num):
            self.start_monitor(i)
        while True:
            time.sleep(0.0001)
            if self.__lock == False:
                if self.queue.empty() == False:
                    self.prog()
            if self.__exit == True:
                break
        # this should be fix with self.monitor_kill(i)
        for i in range(0, self.monitor_num):
            self.monitor_list[i].exit()
        time.sleep(0.2)
        

    def exit(self):
        t = -1
        for i in range (0, 100):
            if self.queue.empty() == False:
                print('%d - exit failed' % (i))
                time.sleep(0.1)
            else:
                t = 0
                break
        print('\033[40m',end='')
        if t is -1:
            print("log_engine is busy")
        self.__exit = True
            
    def prog(self):
        if self.queue.empty() == True:
            return
        temp = self.queue.get()
        #print(temp[3])
        hex_bytes = temp[4]
        temp_hex = "".join("%02x " % b for b in hex_bytes)
        dup = int(-1)
        # for count n - 1 blahblah
        dup_sub = int(0)
        for a in reversed (range (0, self.dup_val)):
            dup_sub += 1
            #print('a : %d' % (a)
            #fprint(' len duplist : %d' % len(self.dup_list))
            if len(self.dup_list) <= a:
                continue
            elif (self.dup_list[a] == temp_hex):
                dup = a
                break
        
        if (len(self.dup_list) >= self.dup_val):
            del (self.dup_list[0])
        self.dup_list.append(temp_hex)
        temp_desc = gen_description(dup, dup_sub)
        temp_ev = gen_ev_str(dup,dup_sub, False)
        #def call(self, ev, nickname, desc, timegap, hex_bytes):
        self.log_write(temp_ev, temp[1], temp[2] ,temp_desc, temp[4])
        self.log_echo(temp_ev, temp[1], temp[2] ,temp_desc, temp[4], color=temp[5])
#(self, port_path, nickname ,hw485io = False, analyze_log = False, print_log = False):
    def add_monitor(self, port_path, nickname='' , color='', hw485io = False):
        idx = self.monitor_num
        self.monitor_num += 1
        __nick = nickname
        if len(__nick) is 0:
            __nick = port_path
            __nick = __nick.replace("/dev/", "")
        ele = com_element(self, idx, port_path, __nick, color=color, hw485io = hw485io)
        self.monitor_list.append(ele)
        return ele

    def start_monitor(self, num):
        if num >= len(self.monitor_list):
            print('no such as num %d monitor' % num)
            return -1
        self.monitor_list[num].start()
        return 0
    
    def kill_monitor(self, num):
        if num >= len(self.monitor_list):
            print('no such as num %d monitor' % num)
            return -1
        ele = self.monitor_list[num].exit()
        self.monitor_num -= 1
        while self.monitor_num != self.monitor_ready:
            time.sleep(0.00001)
            print('wait for kill child %d' % num)
        time.sleep(0.00002)
        self.monitor_list.remove(ele)
        return 0

    def slave_ready_post(self, idx):
        self.monitor_ready += 1

    def slave_close_post(self, idx):
        self.monitor_ready -= 1

    def call(self, ev, nickname, desc, timegap, hex_bytes, color=''):
        while self.__lock == True:
            print("log_engine lock issue")
        # this should be fix to mutex
        self.__lock = True
        temp = []
        temp.append(ev)
        # added this nickname value later (v2).
        temp.append(nickname)
        temp.append(timegap)
        temp.append(desc)
        temp.append(hex_bytes)
        temp.append(color)
        self.queue.put(temp)
        self.__lock = False

    def log_write (self, ev, nickname, timegap, desc, hex_bytes):
        temp = str()
        size = len(hex_bytes)
        temp_size = '%d(% 2x)' % (size, size)
        temp_ascii = "".join(safe_chr(b) for b in hex_bytes)
        temp_hex = "".join("%02x " % b for b in hex_bytes)
        temp = '%s,%s,%s,%d,%s,%s,%s\n' % (ev, nickname, temp_size ,timegap, desc, temp_hex, temp_ascii )
        self.file.write(temp)

    def log_echo (self, ev, nickname, timegap, desc, hex_bytes, color=''):
        size = len(hex_bytes)
        # 3+3+5+24+6+2 = 43 , 2+2+1
        # 8+1=9 is more added for nickname
        # this should be fix later
#        print ('\n'+nickname)
        print(color, end='')
        temp_front = '% 3s\033[1m% 8s\033[21m\033[24m % 3dBytes(%02x)% 24s% 6dms' % (ev, nickname, size, size, desc, timegap)
        t = size//16
        k = size%16
        if k > 0:
            t += 1
        temp = ''
        blank = ' '
        for i in range (0, t):
            if (i+1)*16 <= size:
                d = 16
            else:
                d = (size-(i*16))

            temp_ascii  = "".join(safe_chr(b) for b in hex_bytes[i*16:i*16+d])
            temp_hex    = "".join(" %02x" % b for b in hex_bytes[i*16:i*16+d])
            # need to fill padding reversely. need to fix later.
            if i is 0:
                temp = '%s% 56s \033[1m%-48s\033[21m\033[24m %-16s%s\n' % (color,temp_front, temp_hex, temp_ascii,'\033[40m')
            else:
                temp = temp + '%s% 56s \033[1m%-48s\033[21m\033[24m %-16s%s\n' % (color,blank, temp_hex, temp_ascii,'\033[40m')
        print(temp, end='')
        print('\033[40m',end='')

    def __del__(self):
        n = len(self.monitor_list)
        for i in range (0, n):
            self.monitor_list[i].exit()
            time.sleep(0.001)
        self.file.close()


class com_element(Thread):
    def __init__(self, parent, idx, port_path, nickname, color='', hw485io = False):
        self.ser = serial.Serial(
            port=port_path,
            baudrate=115200,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            bytesize=serial.EIGHTBITS,
            timeout=0.0005
        )
        self.color = color
        self.policy_rtscts = False
        self.__exit = False
        self.nickname = nickname
        self.dt = getmstime()
        self.parent = parent
        self.idx = idx
        self.ready = False
        if hw485io is True:
            self.policy_logger = True
            self.enable_native_rs485_io()

        # need to alert opend very well to parent thread
        print("%s (%s) monitor is opend." % (self.nickname, port_path))
        time.sleep(0.1)
        Thread.__init__(self)

    def run(self):
        self.parent.slave_ready_post(self.idx)
        print("%s entered to start state" % self.nickname)
        while True:
            self.basic_work()
            if self.__exit is True:
                break

    def __del__(self):
        self.ser.close()
        self.parent.slave_close_post(self.idx)
        # alert closed to thread

    def exit(self):
        self.__exit = True
        return self

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

    def basic_work(self):
        time.sleep(0.00005)
        a = self.read_packet()
        if len(a) != 0:
            dy = getmstime()
            __timegap = dy-self.dt
            
            self.parent.call(ev=0, nickname=self.nickname, desc=0, timegap=__timegap, hex_bytes=a, color=self.color)
            self.dt = dy


def main():
    # def __init__(self, port_path, hw485io = False, analyze_log = False, print_log = False):
    #program = app(port_path = '/dev/ttyS1', hw485io=False, analyze_log=True, print_log=True)
    program = analyzer(duplicate_kill=30)
    program.add_monitor('/dev/ttyUSB0', nickname='TX', color='\033[104m')
    program.add_monitor('/dev/ttyUSB1', nickname='RX', color='\033[100m')
    program.start()
    while True:
        time.sleep(0.001)
        key = input('')
        if key is 'q':
            break
    program.exit()


# this function for logging data
    

# for __main__()
main()
