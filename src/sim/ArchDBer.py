from m5.params import *
from m5.proxy import *
from m5.SimObject import *


class ArchDBer(SimObject):
    type = "ArchDBer"
    cxx_header = "sim/arch_db.hh"
    cxx_class = "gem5::ArchDBer"

    cxx_exports = [
        PyBindMethod("start_recording"),
    ]

    arch_db_file = Param.String("", "Where to save arch db")
    dump_from_start = Param.Bool(True, "Dump arch db from start")

    table_cmds = VectorParam.String([], "Tables to create")
