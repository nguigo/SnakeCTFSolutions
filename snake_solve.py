import sys, z3
from miasm.core.utils                      import upck16, pck64
from miasm.core.locationdb                 import LocationDB
from miasm.core.interval                   import interval
from miasm.analysis.dse                    import DSEPathConstraint as DSEPC
from miasm.expression.expression           import ExprInt, ExprLoc, ExprMem
from miasm.jitter.csts                     import PAGE_READ, PAGE_WRITE
from miasm.analysis.sandbox                import Sandbox_Win_x86_64

# Memory dump of the QT string when trying '123456789ABCDEF0' in GUI
qtstring =  b'\x06\x00\x00\x00\x10\x00\x00\x00\x14\x00\x00\x00\x0D\xF0\xAD\xBA' \
            b'\x18\x00\x00\x00\x00\x00\x00\x00\x31\x00\x32\x00\x33\x00\x34\x00' \
            b'\x35\x00\x36\x00\x37\x00\x38\x00\x39\x00\x41\x00\x42\x00\x43\x00' \
            b'\x44\x00\x45\x00\x46\x00\x30\x00\x00\x00\xAD\xBA\x0D\xF0\xAD\xBA'

unicode_string = lambda ba: ' '.join(f'{upck16(ba[i:i+2]):04X}' for i in range(0, len(ba), 2))

flag_ptr = 0x20000018
end_ptr = 0x140004C23
success_ptr = 0x140004C07

max_scount = 0x0
def stop_exec(jitter):
  global max_scount
  success_loc = ExprLoc(dse.loc_db.get_offset_location(success_ptr), 64)
  for path, model in dse.new_solutions.items():
    scount = path.count(success_loc)
    if scount > max_scount:
      candidate = bytearray(0x20)
      for i in range(0x20):
        bb = model.eval(dse.z3_trans.from_expr(dse.memory_to_expr(flag_ptr+i)))
        candidate[i] = bb.as_long() if type(bb)==z3.z3.BitVecNumRef else current[i]
      ustr = candidate.decode('UTF-16')
      print(f'\tHit success bbl {scount} times with: "{ustr[:scount]}"')
      todo.append(bytes(candidate)) # Put it back in the todo list
      max_scount = scount
  return False # This ends execution

forward = lambda j: bool(j.run_at(j.pc))
qt_methods = {'qt5core_??AQString@@QEBA?BVQChar@@H@Z': forward, 'qt5core_?toAscii@QChar@@QEBADXZ': forward,
              'qt5core_?at@QString@@QEBA?BVQChar@@H@Z': forward, 'qt5core_?toLatin1@QChar@@QEBADXZ': forward }

def main():
  global dse, todo, current
  sys.setrecursionlimit(2000) # oof
  # Parse arguments
  parser = Sandbox_Win_x86_64.parser(description="PE sandboxer")
  parser.add_argument("filename", help="PE Filename")
  options = parser.parse_args()
  options.dependencies = True # So we dont need to reimplement qt
  sb = Sandbox_Win_x86_64(LocationDB(), options.filename, options, custom_methods=qt_methods)
  sb.jitter.add_breakpoint(end_ptr, stop_exec) # End condition
  # Setup the qt string memory and a pointer to it
  sb.jitter.vm.add_memory_page(0x10000018, PAGE_READ|PAGE_WRITE, pck64(0x20000000)) # Hooking in here
  sb.jitter.vm.add_memory_page(0x20000000, PAGE_READ|PAGE_WRITE, qtstring) # The initial qstring
  sb.jitter.vm.add_memory_page(0x10000020, PAGE_READ|PAGE_WRITE, b'\x00') # The result
  sb.jitter.cpu.R15 = 0x10000000
  sb.jitter.cpu.RSP = sb.jitter.stack_base+0x8000
  # Setup and attach the DSE
  dse = DSEPC(sb.machine, sb.loc_db, produce_solution=DSEPC.PRODUCE_SOLUTION_PATH_COV)
  sb.jitter.init_run(0x140004B61)
  dse.attach(sb.jitter)
  dse.update_state_from_concrete()
  dse.symbolize_memory(interval([(flag_ptr, flag_ptr+0x20)]))
  # Printable unicode only
  for address in range(flag_ptr, flag_ptr+0x20, 0x2):
    z3_mem = dse.z3_trans.from_expr(dse.eval_expr(ExprMem(ExprInt(address, 64), 16)))
    unicode_constraint = z3.And( \
                            z3.UGE(z3_mem, dse.z3_trans.from_expr(ExprInt(0x0020, 16))), \
                            z3.ULE(z3_mem, dse.z3_trans.from_expr(ExprInt(0x007E, 16))) \
                            )
    dse.cur_solver.add(unicode_constraint )
  snapshot = dse.take_snapshot()
  # Begin run
  todo = [b'\x41\x00'*0x10]
  while todo:
    dse.restore_snapshot(snapshot)
    current = todo.pop()
    sb.jitter.vm.set_mem(flag_ptr, current) # Update the password in jitter memory
    print('-'*40 + f' CONCRETE: {unicode_string(current)}')
    sb.jitter.continue_run()

if __name__ == '__main__':
  main()
