import unittest

from oddeven import countLetters


# Using unittest as it comes preinstalled with Python
# Series of basic and edge cases.
class TestCountLetters(unittest.TestCase):

    def test_abc(self):
        self.assertEqual(countLetters("abc"), "Yes")

    def test_hello_there(self):
        self.assertEqual(countLetters("Hello There"), "No")

    def test_single_digit(self):
        self.assertEqual(countLetters("1"), "No")

    def test_mixed_letters_and_digits(self):
        self.assertEqual(countLetters("ujfhjsfhje872jfsj34"), "No")

    def test_empty_string(self):
        self.assertEqual(countLetters(""), "No")

    def test_one_character(self):
        self.assertEqual(countLetters("w"), "Yes")

    def test_mixed_capitalized(self):
        self.assertEqual(countLetters("AbCdEfGh"), "No")

    def test_digits_punctuation(self):
        self.assertEqual(countLetters("192.0.0.0"), "No")

# Output should be Ran 8 tests in 0.000s OK
if __name__ == "__main__":
    unittest.main()
