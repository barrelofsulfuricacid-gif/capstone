"""Ordered floating comparisons must decode across the whole operand domain.

Regression for capstone-engine/capstone#3051. The v6 decoder carries the
upstream correction missing from v5; this test guards the maintained fork.
"""
import unittest

from capstone import Cs, CS_ARCH_PPC, CS_MODE_32, CS_MODE_64, CS_MODE_BIG_ENDIAN, CS_MODE_LITTLE_ENDIAN


class OrderedFloatCompareTests(unittest.TestCase):
    def test_all_operands_endianness_and_word_modes(self):
        tested = 0
        for bits in (CS_MODE_32, CS_MODE_64):
            for endian, byteorder in ((CS_MODE_BIG_ENDIAN, 'big'), (CS_MODE_LITTLE_ENDIAN, 'little')):
                decoder = Cs(CS_ARCH_PPC, bits | endian)
                decoder.detail = True
                for condition in range(8):
                    for left in range(32):
                        for right in range(32):
                            word = (63 << 26) | (condition << 23) | (left << 16) | (right << 11) | (32 << 1)
                            instructions = list(decoder.disasm(word.to_bytes(4, byteorder), 0x1000))
                            self.assertEqual(len(instructions), 1, (hex(word), bits, byteorder))
                            insn = instructions[0]
                            self.assertEqual(insn.mnemonic, 'fcmpo')
                            self.assertEqual(insn.size, 4)
                            self.assertEqual([insn.reg_name(op.reg) for op in insn.operands],
                                             [f'cr{condition}', f'f{left}', f'f{right}'])
                            tested += 1
        self.assertEqual(tested, 32768)


if __name__ == '__main__':
    unittest.main()
