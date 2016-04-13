# Copyright (c) 2015 Michel Oosterhof <michel@oosterhof.net>
# All rights reserved.

"""
This module ...
"""

import getopt
from random import randint


from cowrie.core.honeypot import HoneyPotCommand

commands = {}

MEM_RANGE= 204800

MEM_TOTAL =  8069256
MEM_USED = 7372920
MEM_BUFF = 410340
MEM_CACHE = 5295748
BUFF = 2166832
CACHE = 5902424
SWP_TOTAL = 3764220
SWP_USED  = 133080


class command_free(HoneyPotCommand):
    """
    free
    """
    def call(self):
        """
        """
        # Parse options or display no files
        try:
            opts, args = getopt.getopt(self.args, 'mh')
        except getopt.GetoptError as err:
            self.do_free()
            return

        # Parse options
        for o, a in opts:
            if o in ('-h'):
                self.do_free(fmt='human')
                return
            elif o in ('-m'):
                self.do_free(fmt='megabytes')
                return
        self.do_free()


    def do_free(self, fmt='bytes'):
        """
        print free statistics
        """
        var_mem = randint(0, MEM_RANGE)
        var_mem_buf = randint(0, MEM_RANGE)
        var_mem_cache = randint(0, MEM_RANGE)
        var_buf = randint(0, MEM_RANGE)
        var_cache = randint(0, MEM_RANGE)
        var_swp = randint(0, MEM_RANGE)

        if fmt=='bytes':
            FREE_BYTES="""                       total       used       free     shared    buffers     cached
            Mem:       """+str(MEM_TOTAL)+'    '+str(MEM_USED + var_mem)+'     '+str(MEM_TOTAL - MEM_USED - var_mem)+'          0     '+str(MEM_BUFF + var_mem_buf)+'    '+str(MEM_CACHE + var_mem_cache)+"""
            -/+ buffers/cache:    """+str(BUFF + var_buf)+'    '+str(CACHE + var_cache)+"""
            Swap:      """+str(SWP_TOTAL)+'     '+str(SWP_USED + var_swp)+'    '+str(SWP_TOTAL - SWP_USED - var_swp)
            self.write(FREE_BYTES+'\n')
        elif fmt=='megabytes':
            FREE_MEGA="""                        total       used       free     shared    buffers     cached
            Mem:       """+str(int(round(MEM_TOTAL / 1024)))+'    '+str(int(round((MEM_USED + var_mem)/1024)))+'     '+str(int(round((MEM_TOTAL - MEM_USED - var_mem)/1024)))+'             0     '+str(int(round((MEM_BUFF + var_mem_buf)/1024)))+'    '+str(int(round((MEM_CACHE + var_mem_cache)/1024)))+"""
            -/+ buffers/cache:    """+str(int(round((BUFF + var_buf)/1024)))+'    '+str(int(round((CACHE + var_cache)/1024)))+"""
            Swap:      """+str(int(round(SWP_TOTAL / 1024)))+'     '+str(int(round((SWP_USED + var_swp)/1024)))+'    '+str(int(round((SWP_TOTAL - SWP_USED - var_swp)/1024)))
            self.write(FREE_MEGA+'\n')
        elif fmt=='human':
            FREE_HUMAN="""                       total     used     free     shared    buffers     cached
            Mem:       """+str(round(MEM_TOTAL / float(1048576), 2 ))+'G    '+str(round((MEM_USED + var_mem)/float(1048576), 2))+'G     '+str(int(round((MEM_TOTAL - MEM_USED - var_mem)/1024)))+'M             0     '+str(int(round((MEM_BUFF + var_mem_buf)/1024)))+'M    '+str(round((MEM_CACHE + var_mem_cache)/float(1048576), 2))+"""G
            -/+ buffers/cache:    """+str(round((BUFF + var_buf)/float(1048576), 2))+'G    '+str(round((CACHE + var_cache)/float(1048576), 2))+"""G
            Swap:      """+str(round(SWP_TOTAL / float(1048576), 2))+'G     '+str(int(round((SWP_USED + var_swp)/1024)))+'M    '+str(round((SWP_TOTAL - SWP_USED - var_swp)/float(1048576), 2))+'G'
            self.write(FREE_HUMAN+'\n')

commands['/usr/bin/free'] = command_free

