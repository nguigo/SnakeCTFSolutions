import os
from miasm2.analysis.sandbox     import Sandbox, Sandbox_Win_x86_64, OS_Win, Arch_x86_64

class OS_Win64(OS_Win):

    def __init__(self, custom_methods, *args, **kwargs):
        from miasm2.jitter.loader.pe import vm_load_pe, vm_load_pe_libs,\
            preload_pe, libimp_pe, vm_load_pe_and_dependencies
        import win_api_x86_64, win_api_x86_64_seh
        methods = win_api_x86_64.__dict__
        methods.update(custom_methods)

        super(OS_Win, self).__init__(methods, *args, **kwargs)

        # Import manager
        libs = libimp_pe()
        self.libs = libs
        win_api_x86_64.winobjs.runtime_dll = libs

        self.name2module = {}
        fname_basename = os.path.basename(self.fname).lower()

        # Load main pe
        with open(self.fname, "rb") as fstream:
            self.pe = vm_load_pe(self.jitter.vm, fstream.read(),
                                 load_hdr=self.options.load_hdr,
                                 name=self.fname,
                                 **kwargs)
            self.name2module[fname_basename] = self.pe

        # Load library
        if self.options.loadbasedll:

            # Load libs in memory
            self.name2module.update(vm_load_pe_libs(self.jitter.vm,
                                                    self.ALL_IMP_DLL,
                                                    libs,
                                                    self.modules_path,
                                                    **kwargs))

            # Patch libs imports
            for pe in self.name2module.itervalues():
                preload_pe(self.jitter.vm, pe, libs)

        if self.options.dependencies:
            vm_load_pe_and_dependencies(self.jitter.vm,
                                        fname_basename,
                                        self.name2module,
                                        libs,
                                        self.modules_path,
                                        **kwargs)

        win_api_x86_64.winobjs.current_pe = self.pe

        # Fix pe imports
        preload_pe(self.jitter.vm, self.pe, libs)
        # Library calls handler
        self.jitter.add_lib_handler(libs, methods)

        # Manage SEH
        if self.options.use_seh:
            win_api_x86_64_seh.main_pe_name = fname_basename
            win_api_x86_64_seh.main_pe = self.pe
            win_api_x86_64.winobjs.hcurmodule = self.pe.NThdr.ImageBase
            win_api_x86_64_seh.name2module = self.name2module
            win_api_x86_64_seh.set_win_gs_0(self.jitter)
            win_api_x86_64_seh.init_seh(self.jitter)

        self.entry_point = self.pe.rva2virt(
            self.pe.Opthdr.AddressOfEntryPoint)


class Sandbox_Win64(Sandbox, Arch_x86_64, OS_Win64):

    def __init__(self, *args, **kwargs):
        Sandbox.__init__(self, *args, **kwargs)

        # reserve stack for local reg
        for _ in xrange(0x4):
            self.jitter.push_uint64_t(0)

        # Pre-stack return address
        self.jitter.push_uint64_t(self.CALL_FINISH_ADDR)

        # Set the runtime guard
        self.jitter.add_breakpoint(self.CALL_FINISH_ADDR, self.__class__.code_sentinelle)

    def run(self, addr=None):
        """
        If addr is not set, use entrypoint
        """
        if addr is None and self.options.address is None:
            addr = self.entry_point
        super(Sandbox_Win64, self).run(addr)

    def call(self, addr, *args, **kwargs):
        """
        Direct call of the function at @addr, with arguments @args
        @addr: address of the target function
        @args: arguments
        """
        prepare_cb = kwargs.pop('prepare_cb', self.jitter.func_prepare_stdcall)
        super(self.__class__, self).call(prepare_cb, addr, *args)

