# kasan, kmasn, info hang
kasan_pattern = "Call Trace:\n([\s\S]*?)\n(RIP: 00|Allocated by task|===)"  # group 0
kasan_pattern2 = "Call Trace:\n([\s\S]*?)\nAllocated by task"  # uaf
kasan_pattern3 = "Call Trace:\n([\s\S]*?)\n==="  # kasan_null_ptr

# group 0 and 1
kernel_bug = "RIP: 0010:([\s\S]*?)Code[\s\S]*R13:[\s\S]*Call Trace:\n([\s\S]*?)\nModules linked in"

# warn
warn = "RIP: 0010:([\s\S]*?)RSP[\s\S]*?Call Trace:\n([\s\S]*?)(Kernel Offset|\<\/IRQ\>|RIP: 00|Modules linked in)"
warn2 = "RIP: 0010:([\s\S]*?)Code[\s\S]*?Call Trace:\n([\s\S]*?)(Kernel Offset|\<\/IRQ\>|RIP: 00|Modules linked in)"
warn3 = "RIP: 0010:([\s\S]*?)Code[\s\S]*?R13:.*?\n([\s\S]*?)(Kernel Offset|\<\/IRQ\>|RIP: 00|Modules linked in)"
warn4 = "RIP: 0010:([\s\S]*?)RSP[\s\S]*?R13:.*?\n([\s\S]*?)(Kernel Offset|\<\/IRQ\>|RIP: 00|Modules linked in)"

pattern2 = "R13:.*\n([\s\S]*?)Kernel Offset"
pattern3 = "Call Trace:\n([\s\S]*?)\n(Modules linked in| ret_from_fork)"
pattern4 = "RIP: 0010:([\s\S]*)Code[\s\S]*?Call Trace:\n([\s\S]*?)(Kernel Offset|entry_SYSCALL)"
pattern5 = "Call Trace:\n([\s\S]*?)\nCode:"
pattern6 = "Call Trace:\n([\s\S]*?)\nirq event stamp:"
