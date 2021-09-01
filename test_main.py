import unittest
import main

class TestMain(unittest.TestCase):
    
    def test_is_email(self):
        self.assertEqual(main.is_email('test@test.com'), True)
        self.assertEqual(main.is_email('test23.test1@test-test.com'), True)
        self.assertEqual(main.is_email('test123.com'), False)
        self.assertEqual(main.is_email(''), False)


if __name__ == '__main__':
    unittest.main()