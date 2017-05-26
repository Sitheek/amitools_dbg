import zmq
import ctypes as c

from musashi import m68k

from label.LabelLib import LabelLib
from label.LabelStruct import LabelStruct
from Log import log_main

class BreakpointType:
  BPT_E = 1
  BPT_R = 2
  BPT_W = 4
  BPT_RW = BPT_R | BPT_W

class MemoryType:
  MEM_M68K = 1

class EventType:
  DBG_EVT_STARTED = 1
  DBG_EVT_PAUSED = 2
  DBG_EVT_STOPPED = 3

  DBG_EVT_MARK_API = 4

class RequestType:
  REQ_GET_REGS = 1
  REQ_SET_REGS = 2

  REQ_GET_REG = 3
  REQ_SET_REG = 4

  REQ_READ_MEM = 5
  REQ_WRITE_MEM = 6

  REQ_ADD_BREAK = 7
  REQ_DEL_BREAK = 8

  REQ_PAUSE = 9
  REQ_RESUME = 10
  REQ_STOP = 11

  REQ_STEP_INTO = 12
  REQ_STEP_OVER = 13

class BreakpointLocal(c.Structure):
  _fields_ = [('length', c.c_int32),
             ('type', c.c_int32),
             ('address', c.c_uint32)]

class DebuggerEventUnion(c.Union):
  _fields_ = [('bpt', BreakpointLocal),
              ('msg', c.c_char * 256),
              ('exit_code', c.c_int32)]

class DebuggerEvent(c.Structure):
  _fields_ = [('type', c.c_int32),
              ('pc', c.c_uint32),
              ('u', DebuggerEventUnion)]

class MemBuffer(c.Structure):
  _fields_ = [('type', c.c_int32),
              ('size', c.c_int32),
              ('address', c.c_uint32),
              ('buffer', c.c_uint8 * 1024)]

class RegVal(c.Structure):
  _fields_ = [('index', c.c_int32),
              ('value', c.c_uint32)]

class RequestStructUnion(c.Union):
  _fields_ = [('regs', c.c_uint32 * (m68k.M68K_REG_IR - m68k.M68K_REG_D0 + 1)),
              ('mem', MemBuffer),
              ('reg', RegVal),
              ('bpt', BreakpointLocal)]

class RequestStruct(c.Structure):
  _fields_ = [('u', RequestStructUnion),
              ('type', c.c_int32)]

class ResponseStructUnion(c.Union):
  _fields_ = [('regs', c.c_uint32 * (m68k.M68K_REG_IR - m68k.M68K_REG_D0 + 1)),
              ('mem', MemBuffer),
              ('reg', RegVal),
              ('msg', c.c_char * 256)]

class ResponseStruct(c.Structure):
  _fields_ = [('u', ResponseStructUnion),
              ('status', c.c_int32)]


class Breakpoint:
  def __init__(self, type, address, length):
    self.type = type
    self.address = address
    self.length = length

class MotorolaHelper:
    def __init__(self, ctx):
        self.ctx = ctx

    def push_32(self, value):
        sp = self.ctx.cpu.r_reg(m68k.M68K_REG_SP)
        self.ctx.cpu.w_reg(m68k.M68K_REG_SP, sp - 4)
        self.dont_check_bp = True
        self.ctx.raw_mem.w32(sp - 4, value)
        self.dont_check_bp = False

    def pull_32(self):
        sp = self.ctx.cpu.r_reg(m68k.M68K_REG_SP)
        self.ctx.cpu.w_reg(m68k.M68K_REG_SP, sp + 4)
        self.dont_check_bp = True
        result = self.ctx.raw_mem.r32(sp)
        self.dont_check_bp = False
        return result

    def jump_pc(self, pc):
        self.ctx.cpu.w_pc(pc)

    def rts_32(self):
        self.jump_pc(self.pull_32())

    def read_imm_16(self):
        pc = self.ctx.cpu.r_pc()
        self.ctx.cpu.w_pc(pc + 2)
        return self.ctx.raw_mem.r16(pc)

    def read_imm_32(self):
        pc = self.ctx.cpu.r_pc()
        self.ctx.cpu.w_pc(pc + 4)
        return self.ctx.raw_mem.r32(pc)

    def AY(self):
        return self.ctx.cpu.r_reg(m68k.M68K_REG_A0 + (self.ctx.cpu.r_reg(m68k.M68K_REG_IR) & 7))

    def EA_AY_AI_8(self):
        return self.AY()

    def EA_AY_AI_32(self):
        return self.EA_AY_AI_8()

    def jsr_32_ai(self):
        ea = self.EA_AY_AI_32()
        self.push_32(self.ctx.cpu.r_pc())
        self.jump_pc(ea)

    def MAKE_INT(self, value, bits):
        mask = (2 ** bits) - 1
        if value & (1 << (bits - 1)):
            return value | ~mask
        else:
            return value & mask

    def MAKE_INT_8(self, value):
        return self.MAKE_INT(value, 8)

    def MAKE_INT_16(self, value):
        return self.MAKE_INT(value, 16)

    def EA_AY_DI_8(self):
        return self.AY() + self.MAKE_INT_16(self.read_imm_16())

    def EA_AY_DI_32(self):
        return self.EA_AY_DI_8()

    def jsr_32_di(self):
        ea = self.EA_AY_DI_32()
        self.push_32(self.ctx.cpu.r_pc())
        self.jump_pc(ea)

    def get_ea_ix(self, An):
        extension = self.read_imm_16()
        Xn = self.ctx.cpu.r_reg(extension >> 12)
        if not (extension & 0x800):
            Xn = self.MAKE_INT_16(Xn)

        return An + Xn + self.MAKE_INT_8(extension)

    def EA_AY_IX_8(self):
        return self.get_ea_ix(self.AY())

    def EA_AY_IX_32(self):
        return self.EA_AY_IX_8()

    def jsr_32_ix(self):
        ea = self.EA_AY_IX_32()
        self.push_32(self.ctx.cpu.r_pc())
        self.jump_pc(ea)

    def EA_AW_8(self):
        return self.MAKE_INT_16(self.read_imm_16())

    def EA_AW_32(self):
        return self.EA_AW_8()

    def jsr_32_aw(self):
        ea = self.EA_AW_32()
        self.push_32(self.ctx.cpu.r_pc())
        self.jump_pc(ea)

    def EA_AL_8(self):
        return self.read_imm_32()

    def EA_AL_32(self):
        return self.EA_AL_8()

    def jsr_32_al(self):
        ea = self.EA_AL_32()
        self.push_32(self.ctx.cpu.r_pc())
        self.jump_pc(ea)

    def get_ea_pcdi(self):
        old_pc = self.ctx.cpu.r_pc()
        return old_pc + self.MAKE_INT_16(self.read_imm_16())

    def EA_PCDI_8(self):
        return self.get_ea_pcdi()

    def EA_PCDI_32(self):
        return self.EA_PCDI_8()

    def jsr_32_pcdi(self):
        ea = self.EA_PCDI_32()
        self.push_32(self.ctx.cpu.r_pc())
        self.jump_pc(ea)

    def get_ea_pcix(self):
        return self.get_ea_ix(self.ctx.cpu.r_pc())

    def EA_PCIX_8(self):
        return self.get_ea_pcix()

    def EA_PCIX_32(self):
        return self.EA_PCIX_8()

    def jsr_32_pcix(self):
        ea = self.EA_PCIX_32()
        self.push_32(self.ctx.cpu.r_pc())
        self.jump_pc(ea)

    def branch_16(self, offset):
        pc = self.ctx.cpu.r_pc()
        self.ctx.cpu.w_pc(pc + self.MAKE_INT_16(offset))

    def bsr_16(self):
        offset = self.read_imm_16()
        pc = self.ctx.cpu.r_pc()
        self.push_32(pc)
        self.ctx.cpu.w_pc(pc - 2)
        self.branch_16(offset)

    def branch_8(self, offset):
        pc = self.ctx.cpu.r_pc()
        self.ctx.cpu.w_pc(pc + self.MAKE_INT_8(offset))

    def bsr_32(self):
        self.push_32(self.ctx.cpu.r_pc())
        self.branch_8(self.ctx.cpu.r_reg(m68k.M68K_REG_IR) & 0xFF)

    def bsr_8(self):
        self.push_32(self.ctx.cpu.r_pc())
        self.branch_8(self.ctx.cpu.r_reg(m68k.M68K_REG_IR) & 0xFF)

    def calc_step_over(self):
        pc = self.ctx.cpu.r_pc()
        sp = self.ctx.cpu.r_reg(m68k.M68K_REG_SP)
        opc = self.read_imm_16()

        dest_pc = None

        # jsr
        if (opc & 0xFFF8) == 0x4E90:
            self.jsr_32_ai()
            self.rts_32()
            dest_pc = self.ctx.cpu.r_pc()
        elif (opc & 0xFFF8) == 0x4EA8:
            self.jsr_32_di()
            self.rts_32()
            dest_pc = self.ctx.cpu.r_pc()
        elif (opc & 0xFFF8) == 0x4EB0:
            self.jsr_32_ix()
            self.rts_32()
            dest_pc = self.ctx.cpu.r_pc()
        elif (opc & 0xFFFF) == 0x4EB8:
            self.jsr_32_aw()
            self.rts_32()
            dest_pc = self.ctx.cpu.r_pc()
        elif (opc & 0xFFFF) == 0x4EB9:
            self.jsr_32_al()
            self.rts_32()
            dest_pc = self.ctx.cpu.r_pc()
        elif (opc & 0xFFFF) == 0x4EBA:
            self.jsr_32_pcdi()
            self.rts_32()
            dest_pc = self.ctx.cpu.r_pc()
        elif (opc & 0xFFFF) == 0x4EBB:
            self.jsr_32_pcix()
            self.rts_32()
            dest_pc = self.ctx.cpu.r_pc()

        # bsr
        elif (opc & 0xFFFF) == 0x6100:
            self.bsr_16()
            self.rts_32()
            dest_pc = self.ctx.cpu.r_pc()
        elif (opc & 0xFFFF) == 0x61FF:
            self.bsr_32()
            self.rts_32()
            dest_pc = self.ctx.cpu.r_pc()
        elif (opc & 0xFF00) == 0x6100:
            self.bsr_8()
            self.rts_32()
            dest_pc = self.ctx.cpu.r_pc()

        self.ctx.cpu.w_pc(pc)
        self.ctx.cpu.w_reg(m68k.M68K_REG_SP, sp)

        return dest_pc

class Debugger:
    def __init__(self, ctx):

        self.motorola_helper = MotorolaHelper(ctx)
        self.ctx = ctx

        self.dbg_evt = DebuggerEvent()
        self.msg_req = RequestStruct()
        self.msg_resp = ResponseStruct()
        self.dbg_active = False
        self.dbg_trace = False
        self.dbg_paused = False
        self.dbg_reset = False
        self.dbg_resetting = False
        self.dbg_boot_found = False
        self.dbg_step_over = False
        self.dbg_step_over_addr = 0
        self.bpt_list = []

        self.dont_check_bp = False

    def add_breakpoint(self, bpt):
        self.bpt_list.append(Breakpoint(bpt.type, bpt.address, bpt.length))

    def bps_are_equal(self, bp1, bp2):
        return (bp1.type == bp2.type) and (bp1.address == bp2.address) and (bp1.length == bp2.length)

    def delete_breakpoint(self, bpt):
        self.bpt_list = [x for x in self.bpt_list if not self.bps_are_equal(x, bpt)]

    def clear_breakpoints(self):
        del self.bpt_list[:]

    def start_server(self, port):
        self.sock_ctx = zmq.Context()
        self.evt_sock = self.sock_ctx.socket(zmq.PAIR)
        self.msg_sock = self.sock_ctx.socket(zmq.REP)

        self.evt_sock.connect("tcp://localhost:%d" % (port + 0))
        self.msg_sock.bind("tcp://*:%d" % (port + 1))

        log_main.debug("Debugger started. Waiting for connection...\n")

        while True:
            if self.is_socket_available(self.evt_sock, zmq.POLLIN | zmq.POLLOUT):
                log_main.debug("Debugging connection established.\n")
                break

    def stop_server(self):
        self.evt_sock.close()
        self.msg_sock.close()
        self.sock_ctx.destroy()

    def activate_debugger(self):
        self.dbg_active = True

    def deactivate_debugger(self):
        self.dbg_active = False

    def start_debugger(self, port):
        if self.dbg_active:
            return

        self.start_server(port)
        self.activate_debugger()

    def resume_debugger(self):
        self.dbg_trace = False
        self.dbg_paused = False

    def detach_debugger(self):
        self.clear_breakpoints()
        self.resume_debugger()

    def stop_debugger(self, exit_code):
        self.dbg_evt.u.exit_code = exit_code
        self.dbg_evt.type = EventType.DBG_EVT_STOPPED
        self.send_sock_msg(self.evt_sock, self.dbg_evt)

        self.detach_debugger()
        self.stop_server()
        self.deactivate_debugger()

    def pause_debugger(self):
        self.dbg_trace = True
        self.dbg_paused = True

        self.dbg_evt.type = EventType.DBG_EVT_PAUSED
        self.dbg_evt.pc = self.ctx.cpu.r_pc()
        self.send_sock_msg(self.evt_sock, self.dbg_evt)

    def set_step_over(self):
        self.motorola_helper.rts_32()
        self.dbg_step_over = True
        self.dbg_step_over_addr = self.ctx.cpu.r_pc()

    def process_debug(self):
        handled_event = False

        if (not self.dbg_active) or self.dbg_reset or self.dbg_resetting:
            return

        pc = self.ctx.cpu.r_pc()
        sp = self.ctx.cpu.r_reg(m68k.M68K_REG_SP)

        #'''
        r = self.ctx.label_mgr.get_label(pc)
        if r is not None:
            if isinstance(r, LabelLib):
                if pc < r.lib_base:
                    name = r._get_fd_str(r.lib_base - pc)
                    self.dbg_evt.type = EventType.DBG_EVT_MARK_API
                    self.dbg_evt.pc = self.ctx.cpu.r_reg(m68k.M68K_REG_PPC)
                    self.dbg_evt.u.msg = name
                    self.send_sock_msg(self.evt_sock, self.dbg_evt)
                    # print "name = %s" % name
        #'''

        # label, sym, src = self.ctx.label_mgr.get_disasm_info(pc)
        # print "label = %s, sym = %s, src = %s" % (label, sym, src)

        if not self.dbg_boot_found:
            if pc == self.ctx.process.prog_start:
                self.dbg_boot_found = True
                self.dbg_paused = True

                self.dbg_evt.type = EventType.DBG_EVT_STARTED
                self.dbg_evt.pc = self.ctx.process.prog_start
                self.dbg_evt.u.msg = self.ctx.process.bin_file
                self.send_sock_msg(self.evt_sock, self.dbg_evt)

        if self.dbg_trace:
            self.dbg_trace = False
            self.dbg_paused = True

            self.dbg_evt.type = EventType.DBG_EVT_PAUSED
            self.dbg_evt.pc = pc
            self.send_sock_msg(self.evt_sock, self.dbg_evt)

            handled_event = True

        if not self.dbg_paused:
            if self.dbg_step_over:
                if pc == self.dbg_step_over_addr:
                    self.dbg_step_over = False
                    self.dbg_step_over_addr = 0

                    self.dbg_paused = True

            self.check_breakpoint(ord('X'), 1, pc, pc)
            if self.dbg_paused:
                self.dbg_evt.type = EventType.DBG_EVT_PAUSED
                self.dbg_evt.pc = pc
                self.send_sock_msg(self.evt_sock, self.dbg_evt)

                handled_event = True

        if self.dbg_boot_found and (not handled_event) and self.dbg_paused:
            self.dbg_evt.type = EventType.DBG_EVT_PAUSED
            self.dbg_evt.pc = pc
            self.send_sock_msg(self.evt_sock, self.dbg_evt)

        while self.dbg_paused:
            self.process_commands()

    def process_commands(self):
        self.msg_req = self.recv_sock_msg(self.msg_sock, 0)

        if self.msg_req is None:
            return

        self.msg_resp = ResponseStruct()

        if self.msg_req.type == RequestType.REQ_GET_REGS:
            for i in xrange(m68k.M68K_REG_IR - m68k.M68K_REG_D0 + 1):
                self.msg_resp.u.regs[i] = self.ctx.cpu.r_reg(i)
        elif self.msg_req.type == RequestType.REQ_SET_REGS:
                for i in xrange(m68k.M68K_REG_IR - m68k.M68K_REG_D0 + 1):
                    self.ctx.cpu.w_reg(i, self.msg_req.u.regs[i])
        elif self.msg_req.type == RequestType.REQ_GET_REG:
            self.msg_resp.u.reg.index = self.msg_req.u.reg.index
            self.msg_resp.u.reg.value = self.msg_req.u.reg.value
        elif self.msg_req.type == RequestType.REQ_SET_REG:
            self.ctx.cpu.w_reg(self.msg_req.u.reg.index, self.msg_req.u.reg.value)
        elif self.msg_req.type == RequestType.REQ_READ_MEM:
            self.msg_resp.u.mem.type = self.msg_req.u.mem.type
            self.msg_resp.u.mem.size = self.msg_req.u.mem.size

            self.dont_check_bp = True
            for i in xrange(self.msg_req.u.mem.size):
                self.msg_resp.u.mem.buffer[i] = self.ctx.raw_mem.r8(self.msg_req.u.mem.address + i)
            self.dont_check_bp = False

        elif self.msg_req.type == RequestType.REQ_WRITE_MEM:
            self.msg_resp.u.mem.size = self.msg_req.u.mem.size
            self.msg_resp.u.mem.type = self.msg_req.u.mem.type

            self.dont_check_bp = True
            for i in xrange(self.msg_req.u.mem.size):
                self.ctx.raw_mem.w8(self.msg_req.u.mem.address + i, self.msg_req.u.mem.buffer[i])
            self.dont_check_bp = False

        elif self.msg_req.type == RequestType.REQ_ADD_BREAK:
            self.add_breakpoint(self.msg_req.u.bpt)
            # return
        elif self.msg_req.type == RequestType.REQ_DEL_BREAK:
            self.delete_breakpoint(self.msg_req.u.bpt)
            # return
        elif self.msg_req.type == RequestType.REQ_PAUSE:
            self.pause_debugger()
            # return
        elif self.msg_req.type == RequestType.REQ_RESUME:
            self.resume_debugger()
            # return
        elif self.msg_req.type == RequestType.REQ_STOP:
            self.detach_debugger()
            # return
        elif self.msg_req.type == RequestType.REQ_STEP_INTO:
            if (self.dbg_paused):
                self.dbg_trace = True
                self.dbg_paused = False
                # return
        elif self.msg_req.type == RequestType.REQ_STEP_OVER:
            if self.dbg_paused:
                dest_pc = self.motorola_helper.calc_step_over()

                if dest_pc is not None:
                    self.dbg_step_over = True
                    self.dbg_step_over_addr = dest_pc
                else:
                    self.dbg_step_over = False
                    self.dbg_trace = True

                self.dbg_paused = False
        else:
            self.msg_resp.u.msg = "Unknown request code = %d" % self.msg_req.type
            self.msg_resp.status = 1

        self.send_sock_msg(self.msg_sock, self.msg_resp)

    def check_breakpoint(self, mode, width, addr, val):
        if not self.dbg_active or self.dbg_reset or self.dont_check_bp:
            return 0

        pc = self.ctx.cpu.r_pc()
        type = BreakpointType.BPT_E
        mode = chr(mode)

        if mode == 'R':
            type = BreakpointType.BPT_R
        elif mode == 'W':
            type = BreakpointType.BPT_W

        for bpt in self.bpt_list:
            if not (bpt.type & type):
                continue
            if (addr <= bpt.address + bpt.length) and ((addr + width) >= bpt.address):
                self.dbg_paused = True
                break

        return 0

    def is_socket_available(self, sock, events):
        poller = zmq.Poller()
        poller.register(sock, events)

        socks = dict(poller.poll(1000))
        poller.unregister(sock)

        if sock not in socks:
            return False

        return True

    def send_sock_msg(self, sock, buf):
        # if not self.is_socket_available(sock, zmq.POLLOUT):
        #   return
        if not self.dbg_active:
            return

        sock.send(buf)

    def recv_sock_msg(self, sock, flags):
        # if not self.is_socket_available(sock, zmq.POLLIN):
        #  return None
        if not self.dbg_active:
            return

        try:
            buf = sock.recv(flags=flags)
            retn = RequestStruct()
            c.memmove(c.byref(retn), buf, c.sizeof(RequestStruct))
            return retn
        except zmq.ZMQError, e:
            if e.errno == zmq.EAGAIN:
                return None

            return None