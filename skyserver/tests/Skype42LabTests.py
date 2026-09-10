"""Offline structural/ABI checks; does NOT assert that Skype can log in."""
import importlib.util
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("lab", ROOT / "tools" / "Build-Skype42Lab.py")
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EFLAGS, UC_X86_REG_EIP, UC_X86_REG_ESP


class LabTests(unittest.TestCase):
    def test_exact_patch_guards_and_padding(self):
        data = bytearray(b"old\0neighbor")
        lab.replace_exact(data, 0, b"old\0", b"x\0")
        self.assertEqual(data, b"x\0\0\0neighbor")
        with self.assertRaises(ValueError):
            lab.replace_exact(data, 0, b"old\0", b"new\0")
        with self.assertRaises(ValueError):
            lab.replace_exact(data, 0, b"x\0", b"longer")
        with self.assertRaises(ValueError):
            lab.span(data, -1, 1)

    def test_refuses_unknown_image_before_keys(self):
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            lab.build(b"not original", b"not image", ROOT, "127.0.0.1")

    def test_private_thunks_are_translated_but_ordinals_preserved(self):
        image = bytearray(4096)
        delta = 0x100
        struct.pack_into("<5I", image, 0, 0x200, 0, 0, 0x100, 0x220)
        image[0x200:0x200 + 10] = b"WS2_32.dll"
        struct.pack_into("<3I", image, 0x300, 0x400, 0x80000013, 0)
        struct.pack_into("<3I", image, 0x320, 0x400, 0x80000013, 0)
        image[0x502:0x507] = b"send\0"
        records, info = lab.import_descriptors(image, 0, 40, delta)
        self.assertEqual(struct.unpack("<5I", records[0]), (0x300, 0, 0, 0x200, 0x320))
        self.assertEqual(struct.unpack_from("<3I", image, 0x300), (0x500, 0x80000013, 0))
        self.assertEqual(image[0x300:0x30c], image[0x320:0x32c])
        self.assertEqual(info[0]["symbols"], ["send", "#19"])

    def test_startup_call_order_arguments_and_stack_balance(self):
        mu = Uc(UC_ARCH_X86, UC_MODE_32)
        mu.mem_map(lab.BASE, lab.IMAGE_SIZE + 4096)
        mu.mem_map(0x20000000, 4096)
        stack = 0x20000800
        entry = lab.BASE + lab.IMAGE_SIZE
        end = 0x1019FD4
        mu.mem_write(entry, lab.startup_stub(lab.IMAGE_SIZE, lab.IMAGE_SIZE + 4096))
        mu.mem_write(0x52B690, b"\xc3")
        mu.mem_write(0xA90EE6, b"\xc2\x0c\x00")
        mu.reg_write(UC_X86_REG_ESP, stack)
        mu.reg_write(UC_X86_REG_EFLAGS, 0x402)
        calls = []

        def observe(emulator, at, size, user):
            esp = emulator.reg_read(UC_X86_REG_ESP)
            if at == 0x52B690:
                calls.append(at)
                self.assertEqual(emulator.reg_read(UC_X86_REG_EAX), lab.BASE)
                self.assertEqual(struct.unpack("<I", emulator.mem_read(esp + 4, 4))[0], lab.IMAGE_SIZE + 4096)
            elif at == 0xA90EE6:
                calls.append(at)
                self.assertEqual(struct.unpack("<3I", emulator.mem_read(esp + 4, 12)), (0x4F1000, 1, 0))
                self.assertEqual(emulator.mem_read(0xD19A98, 1), b"\1")

        mu.hook_add(UC_HOOK_CODE, observe)
        mu.emu_start(entry, end, timeout=1000000, count=100)
        self.assertEqual(mu.reg_read(UC_X86_REG_EIP), end)
        self.assertEqual(mu.reg_read(UC_X86_REG_ESP), stack)
        self.assertEqual(mu.reg_read(UC_X86_REG_EFLAGS) & 0x400, 0)
        self.assertEqual(calls, [0x52B690, 0xA90EE6])

    def test_actual_image_imports_and_original_backup(self):
        directory = ROOT / "diagnostics" / "pe-analysis-20260907-233415"
        if not directory.exists():
            self.skipTest("Exact local original and static image are not available")
        original = (directory / "Skype-original.exe").read_bytes()
        image = (directory / "Skype-uncompressed.image.bin").read_bytes()
        data, manifest = lab.build(original, image, ROOT / "private-keys", "192.168.1.101")
        self.assertEqual(lab.sha(original), lab.ORIGINAL_HASH)
        self.assertEqual(len(manifest["imports"]), 47)
        self.assertEqual(len(data), lab.IMAGE_SIZE + 4096)
        pe = lab.pefile.PE(data=data)
        self.assertEqual(pe.FILE_HEADER.NumberOfSections, 8)
        self.assertEqual(pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size, 0)
        self.assertEqual(pe.OPTIONAL_HEADER.CheckSum, 0)
        self.assertEqual(len(manifest["patches"]), 20)
        self.assertEqual(data[0x16FCF4:0x16FCFB], bytes.fromhex('6a 01 68 8c b9 c8 00'))
        self.assertEqual(data[lab.SEEDS_RVA:lab.SEEDS_RVA + lab.SEEDS_COUNT * 6], bytes.fromhex('c0a80165303e') * 200)
        # Known multicast, localhost and version constants must not be rewritten.
        for at, length in ((0x8BBD12, 22), (0x8CA6A8, 10), (0x983DBE, 10)):
            self.assertEqual(data[at:at + length], image[at:at + length])
        self.assertTrue(all(row["expected"] == row["actual"] for row in lab.checksum_table(image)))
        self.assertTrue(all(row["expected"] == row["actual"] for row in lab.checksum_table(data)))
        self.assertEqual(data[0x12AC10:0x12AF16], image[0x12AC10:0x12AF16])
        self.assertEqual(self.run_original_integrity_routine(data), 1)
        tampered = bytearray(data)
        tampered[0x870EC9] ^= 1
        self.assertEqual(self.run_original_integrity_routine(tampered), 0)
        self.assertTrue(lab.verify_table_signature(image))
        self.assertTrue(lab.verify_table_signature(data))
        tampered[0x12BD18] ^= 1
        self.assertFalse(lab.verify_table_signature(tampered))
        self.run_periodic_integrity_routine(data)

    def test_bootstrap_exception_admits_only_configured_private_ip(self):
        from unicorn.x86_const import UC_X86_REG_EBX, UC_X86_REG_ESI
        source = ROOT / 'diagnostics' / 'pe-analysis-20260907-233415' / 'Skype-uncompressed.image.bin'
        if not source.exists():
            self.skipTest('Static image is not present')
        original = source.read_bytes()
        for configured in ('192.168.1.101', '127.0.0.1', '10.0.0.2'):
            image = bytearray(original)
            stub = lab.bootstrap_address_exception(image, lab.IMAGE_SIZE + 0x80, configured)
            for address, accepted in ((configured, True), ('192.168.1.102', False), ('10.9.8.7', False), ('8.8.8.8', True)):
                mu = Uc(UC_ARCH_X86, UC_MODE_32)
                mu.mem_map(lab.BASE, lab.IMAGE_SIZE + 4096)
                mu.mem_write(lab.BASE, bytes(image))
                mu.mem_write(lab.BASE + lab.IMAGE_SIZE + 0x80, stub)
                mu.mem_map(0x20000000, 4096)
                mu.reg_write(UC_X86_REG_ESP, 0x20000800)
                ip = int(lab.ipaddress.IPv4Address(address))
                mu.reg_write(UC_X86_REG_EAX, ip & 0xFF000000)
                mu.reg_write(UC_X86_REG_ESI, ip)
                mu.reg_write(UC_X86_REG_EBX, 12350)
                mu.hook_add(UC_HOOK_CODE, lambda emu, at, size, user: emu.emu_stop() if at in (0x64BDFF, 0x64BE27) else None)
                mu.emu_start(0x64BDB2, 0x64BE28, timeout=1000000, count=100)
                self.assertEqual(mu.reg_read(UC_X86_REG_EIP), 0x64BE27 if accepted else 0x64BDFF)
                self.assertEqual(struct.unpack('<II', mu.mem_read(0x20000830, 8)), (ip, 12350))

    def test_endpoint_exception_preserves_other_addresses_and_ports(self):
        from unicorn.x86_const import UC_X86_REG_EDX, UC_X86_REG_ESI
        source = ROOT / 'diagnostics' / 'pe-analysis-20260907-233415' / 'Skype-uncompressed.image.bin'
        if not source.exists():
            self.skipTest('Static image is not present')
        original = source.read_bytes()
        for configured in ('192.168.1.101', '127.0.0.1', '10.0.0.2'):
            image = bytearray(original)
            stub = lab.endpoint_address_exception(image, lab.IMAGE_SIZE + 0x500, configured)
            mu = Uc(UC_ARCH_X86, UC_MODE_32)
            mu.mem_map(lab.BASE, lab.IMAGE_SIZE + 4096)
            mu.mem_write(lab.BASE, bytes(image))
            mu.mem_write(lab.BASE + lab.IMAGE_SIZE + 0x500, stub)
            mu.mem_map(0x20000000, 4096)
            cases = [(configured, port, 1) for port in lab.SERVER_PORTS]
            cases += [(configured, 0, 0), (configured, 65535, 0), (configured, 65536, 0),
                      ('192.168.1.102', 12350, 0), ('10.9.8.7', 33033, 0),
                      ('0.0.0.0', 12350, 0), ('8.8.8.8', 12350, 1), ('8.8.8.8', 65536, 0)]
            for address, port, accepted in cases:
                mu.reg_write(UC_X86_REG_ESP, 0x20000800)
                mu.mem_write(0x20000800, struct.pack('<I', 0x56E3A8))
                mu.mem_write(0x20000100, struct.pack('<II', int(lab.ipaddress.IPv4Address(address)), port))
                mu.reg_write(UC_X86_REG_EDX, 0x20000100)
                mu.reg_write(UC_X86_REG_ESI, 0x12345678)
                mu.emu_start(0x56E350, 0x56E3A8, timeout=1000000, count=150)
                self.assertEqual(mu.reg_read(UC_X86_REG_EAX), accepted, (address, port))
                self.assertEqual(mu.reg_read(UC_X86_REG_ESP), 0x20000804)
                self.assertEqual(mu.reg_read(UC_X86_REG_ESI), 0x12345678)

    @staticmethod
    def run_original_integrity_routine(image):
        from unicorn import UC_PROT_READ, UC_PROT_EXEC
        mu = Uc(UC_ARCH_X86, UC_MODE_32)
        mu.mem_map(lab.BASE, len(image), UC_PROT_READ)
        mu.mem_write(lab.BASE, bytes(image))
        mu.mem_protect(0x52A000, 4096, UC_PROT_READ | UC_PROT_EXEC)
        mu.mem_map(0x20000000, 65536)
        stack, end = 0x20008000, 0x52AF16
        mu.mem_write(stack, struct.pack("<I", end))
        mu.reg_write(UC_X86_REG_ESP, stack)
        mu.emu_start(0x52AC10, end, timeout=15000000, count=200000000)
        if mu.reg_read(UC_X86_REG_EIP) != end:
            raise ValueError("Integrity emulation did not return")
        return mu.reg_read(UC_X86_REG_EAX) & 255

    @staticmethod
    def run_periodic_integrity_routine(image):
        from unicorn import UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
        mu = Uc(UC_ARCH_X86, UC_MODE_32)
        mu.mem_map(lab.BASE, len(image), UC_PROT_READ)
        mu.mem_write(lab.BASE, bytes(image))
        # Only the original check, bignum, memcpy/memset and GS-cookie routines.
        # No Windows API emulation or arbitrary process attachment is involved.
        for at, size in ((0x52B000, 8192), (0x90C000, 8192), (0xA90000, 4096), (0xA94000, 8192)):
            mu.mem_protect(at, size, UC_PROT_READ | UC_PROT_EXEC)
        mu.mem_protect(0xD15000, 4096, UC_PROT_READ | UC_PROT_WRITE)
        mu.mem_map(0x20000000, 0x100000)
        stack, end = 0x200FF000, 0x52C5B0
        for _ in range(13):
            mu.mem_write(stack, struct.pack("<I", end))
            mu.reg_write(UC_X86_REG_ESP, stack)
            mu.emu_start(0x52C170, end, timeout=10000000, count=100000000)
            if mu.reg_read(UC_X86_REG_EIP) != end or mu.reg_read(UC_X86_REG_ESP) != stack + 4:
                raise ValueError("Periodic integrity check did not return cleanly")


if __name__ == "__main__":
    unittest.main(verbosity=2)
