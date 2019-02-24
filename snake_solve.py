import z3
from miasm2.core.utils                      import upck16, pck64
from miasm2.analysis.dse                    import DSEPathConstraint as DSEPC
from miasm2.expression.expression           import ExprInt, ExprId, ExprMem, ExprAff
from miasm2.jitter.csts                     import PAGE_READ, PAGE_WRITE
from sandbox_win64                          import Sandbox_Win64

# Memory dump of the QT string when trying '123456789ABCDEF0' in GUI
qtstring =  '\x06\x00\x00\x00\x10\x00\x00\x00\x14\x00\x00\x00\x0D\xF0\xAD\xBA' \
            '\x18\x00\x00\x00\x00\x00\x00\x00\x31\x00\x32\x00\x33\x00\x34\x00' \
            '\x35\x00\x36\x00\x37\x00\x38\x00\x39\x00\x41\x00\x42\x00\x43\x00' \
            '\x44\x00\x45\x00\x46\x00\x30\x00\x00\x00\xAD\xBA\x0D\xF0\xAD\xBA'

unicode_string = lambda ba: ' '.join(['%04x'%(upck16(bytearray([ba[i], ba[i+1]]))) for i in range(0, len(ba), 2)])

class FinishException(Exception):
  def __init__(self, password):
    super(FinishException, self).__init__('Found incremental solution')
    self.password = password

def set_unicode_ranges(address, ranges):
  mem = ExprMem(ExprInt(address, 64), 16)
  z3_mem = dse.z3_trans.from_expr(dse.eval_expr(mem))
  for l, u in ranges:
    lower_bound = z3.UGT(z3_mem, dse.z3_trans.from_expr(ExprInt(l, 16)))
    upper_bound = z3.UGT(dse.z3_trans.from_expr(ExprInt(u, 16)), z3_mem)
    constraint = z3.And(lower_bound, upper_bound)
    dse.cur_solver.add(constraint)

def stop_exec(jitter):
  dse.cur_solver.check()
  # If we reached a new block
  for bbl, model in dse.new_solutions.items():
    bbl_addr = dse.loc_db.get_location_offset(bbl.loc_key) # Get the bbl offset the DSE hit
    # Capture the values of the two symbolized bytes
    current[index] =  model.eval(dse.z3_trans.from_expr(dse.memory_to_expr(0x20000018+index))).as_long()
    current[index+1] = model.eval(dse.z3_trans.from_expr(dse.memory_to_expr(0x20000018+index+1))).as_long()
    if bbl_addr == 0x140004C07:
      print u'\tHit success bbl at %x with tentative password: %s' % (bbl_addr, current.decode('UTF-16'))
      raise FinishException(current)
    else:
      print u'\tHit new bbl at %x with: %s' % (bbl_addr, unicode_string(current))
      todo.append(current) # Put it back in the todo list
  return False # This ends execution

def forward(jitter):
  jitter.run_at(jitter.pc)

qt_methods = {'qt5core_??AQString@@QEBA?BVQChar@@H@Z': forward, 'qt5core_?toAscii@QChar@@QEBADXZ': forward}

def main():
  global dse, todo, index, current
  # Parse arguments
  parser = Sandbox_Win64.parser(description="PE sandboxer")
  parser.add_argument("filename", help="PE Filename")
  options = parser.parse_args()
  options.jitter = 'llvm'
  options.use_seh = True # So we dont need to reimplement qt crap
  options.dependencies = True # So we dont need to reimplement qt crap
  sb = Sandbox_Win64(options.filename, options, custom_methods=qt_methods)
  sb.jitter.add_breakpoint(0x140004C23, stop_exec) # End condition
  sb.jitter.cpu.RSP = 0x13F000 # default stack at 13000
  # Setup our bogus qt string and a pointer to it
  sb.jitter.vm.add_memory_page(0x10000018, PAGE_READ|PAGE_WRITE, pck64(0x20000000)) # Hooking in here
  sb.jitter.vm.add_memory_page(0x20000000, PAGE_READ|PAGE_WRITE, qtstring) # The bogus qstring
  sb.jitter.vm.add_memory_page(0x10000020, PAGE_READ|PAGE_WRITE, '\x00') # The result
  sb.jitter.cpu.R15 = 0x10000000
  # Stick the symbolic execution on it
  dse = DSEPC(sb.machine, produce_solution=DSEPC.PRODUCE_SOLUTION_CODE_COV)
  sb.jitter.init_run(0x140004B61)
  dse.attach(sb.jitter)
  dse.update_state_from_concrete()
  snapshot = dse.take_snapshot()
  # Begin run
  password = bytearray('\xFF\xFF') # Just one bogus unicode char to start with
  todo = [password]
  index = 0
  new_run = False
  while todo:
    current = todo.pop()
    dse.restore_snapshot(snapshot, keep_known_solutions=not new_run)
    # Update the password in jitter memory
    for i, c in enumerate(current):
      sb.jitter.eval_expr(ExprAff(ExprMem(ExprInt(0x20000018+i, 64), 8), ExprInt(int(c), 8)))
    # Symbolize the next unicode char (2 bytes)
    dse.update_state({ExprMem(ExprInt(0x20000018+index, 64), 8) : dse.memory_to_expr(0x20000018+index), \
                        ExprMem(ExprInt(0x20000018+index+1, 64), 8) : dse.memory_to_expr(0x20000018+index+1)})
    set_unicode_ranges(0x20000018+index, {(0x0020, 0x007E)}) # Ensure DSE only finds printable unicode chars solutions
    try:
      print 'RUN:  %s %s' % (current if new_run else unicode_string(current), '(new run)' if new_run else '')
      sb.jitter.continue_run()
    except FinishException as fini:
      password = fini.password+bytearray('\xFF\xFF')
      todo = [password]
      index+=2
      new_run = True
      continue
    new_run = False

if __name__ == '__main__':
  main()
