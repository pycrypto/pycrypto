test_data = [
        ('0000000100020003', '11fbed2b01986de5',
         '00010002000300040005000600070008'),
        ('0102030405060708', '540e5fea18c2f8b1',
         '00010002000300040005000600070008'),
        ('0019324b647d96af', '9f0a0ab6e10ced78',
         '00010002000300040005000600070008'),
        ('f5202d5b9c671b08', 'cf18fd7355e2c5c5',
         '00010002000300040005000600070008'),
        ('fae6d2beaa96826e', '85df52005608193d',
         '00010002000300040005000600070008'),
        ('0a141e28323c4650', '2f7de750212fb734',
         '00010002000300040005000600070008'),
        ('050a0f14191e2328', '7b7314925de59c09',
         '00010002000300040005000600070008'),
        ('0102030405060708', '3ec04780beff6e20',
         '0005000A000F00140019001E00230028'),
        ('0102030405060708', '97bcd8200780da86',
         '3A984E2000195DB32EE501C8C47CEA60'),
        ('05320a6414c819fa', '65be87e7a2538aed',
         '006400C8012C019001F4025802BC0320'),
        ('0808080808080808', 'f5db1ac45e5ef9f9',
         '9D4075C103BC322AFB03E7BE6AB30006'),
    ];


def get_tests(config={}):
    from Crypto.Cipher import AIDEA
    from common import make_block_tests

    tests = make_block_tests(AIDEA, "AIDEA", test_data)
    return tests

if __name__ == '__main__':
    import unittest
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
