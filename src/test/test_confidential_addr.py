import unittest
from util import *

CA_PREFIX_LIQUID = 0x0c
EC_PUBLIC_KEY_LEN = 33

HARDENED = 0x80000000
VER_MAIN_PRIVATE = 0x0488ADE4

class CATests(unittest.TestCase):

    def test_confidential_addr(self):
        """Tests for confidential addresses"""

        # The (Liquid) address that is to be blinded
        addr = 'Q7qcjTLsYGoMA7TjUp97R6E6AM5VKqBik6'
        # The blinding pubkey
        pubkey_hex = '02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623'
        # The resulting confidential address
        addr_c = utf8('VTpz1bNuCALgavJKgbAw9Lpp9A72rJy64XPqgqfnaLpMjRcPh5UHBqyRUE4WMZ3asjqu7YEPVAnWw2EK')

        # Test we can extract the original address
        ret, result = wally_confidential_addr_to_addr(addr_c, CA_PREFIX_LIQUID)
        self.assertEqual((ret, result), (WALLY_OK, addr))

        # Test we can extract the blinding pubkey
        out, out_len = make_cbuffer('00' * EC_PUBLIC_KEY_LEN)
        ret = wally_confidential_addr_to_ec_public_key(addr_c, CA_PREFIX_LIQUID, out, out_len)
        self.assertEqual(ret, WALLY_OK)
        _, out_hex = wally_hex_from_bytes(out, out_len)
        self.assertEqual(utf8(pubkey_hex), utf8(out_hex))

        # Test we can re-generate the confidential address from its inputs
        ret, new_addr_c = wally_confidential_addr_from_addr(utf8(addr), CA_PREFIX_LIQUID, out, out_len)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(utf8(new_addr_c), addr_c)

    def test_elements(self):
        seed = create_string_buffer(64)
        bip39_mnemonic_to_seed(b"alcohol woman abuse must during monitor noble actual mixed trade anger aisle", b"", seed, 64)
        self.assertEqual(seed.raw.hex(), '1ebf38d0b1fc10ac12059141276c1b8b7a410ba43d04bbe9f3a371d884a304400b6a39fda34e5b282a3717663fb337954df3dadf802a4cba3d008d5e2988f70a')

        master = ext_key()
        ret = bip32_key_from_seed(seed, len(seed), VER_MAIN_PRIVATE, 0, byref(master))
        self.assertEqual(ret, WALLY_OK)

        # Blinding key derivation
        path = [HARDENED | 77]
        path = (c_uint * len(path))(*path)
        node = ext_key()
        ret = bip32_key_from_parent_path(byref(master), path, len(path), 0, byref(node))
        self.assertEqual(ret, WALLY_OK)

        self.assertEqual(bytes(node.priv_key[1:]).hex(), '9c7f4057b4caae46de6dc22b569801e47e9d1fdcba84bdbe87670cb1836a3fe7')


if __name__ == '__main__':
    unittest.main()
