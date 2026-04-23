import doctest
import string

""""
  Reverse the given integer number using ONLY arithmetic operations.

  >>> reverse_number(12345)
  54321

  >>> reverse_number(758148293)
  392841857

  >>> reverse_number(1)
  1

  >>> reverse_number(12321)
  12321
"""
def reverse_number(number):
   reversed_num = 0
   n = abs(number)
   while n > 0:
    reversed_num = reversed_num * 10 + n % 10
    n //= 10
    return reversed_num if number >= 0 else -reversed_num
doctest.run_docstring_examples(reverse_number, globals())

def reverse_str(s):
  """
  Reverse the given string WITHOUT using any auxiliary methods or functions.

  >>> reverse_str("Hello World")
  'dlroW olleH'

  >>> reverse_str("Erised stra ehru oyt ube cafru oyt on wohsi")
  'ishow no tyo urfac ebu tyo urhe arts desirE'

  >>> reverse_str("siht ekil dnuos I dna mra eht ma I")
  'I am the arm and I sound like this'

  >>> reverse_str("?")
  '?'
  """
  result = ''
  i = len(s) - 1
  while i >= 0:
    result += s[i]
    i -= 1
  return result

doctest.run_docstring_examples(reverse_str, globals())


def swap_dictionary(d):
  """
  Swap the keys/values of the given dictionary. Since values may be repeated, the new dictionary will have a list of keys as values.

  >>> swap_dictionary({"a" : "b", "b" : "c", "c" : "d", "d" : "e", "e" : "f", "f" : "b"})
  {'b': ['a', 'f'], 'c': ['b'], 'd': ['c'], 'e': ['d'], 'f': ['e']}

  >>> swap_dictionary({"Jan": "Winter", "Fev": "Winter", "Mar": "Spring", "Apr": "Spring", "Dec": "Winter", "Jul" : "Summer"})
  {'Winter': ['Jan', 'Fev', 'Dec'], 'Spring': ['Mar', 'Apr'], 'Summer': ['Jul']}

  >>> swap_dictionary({"Arya": "Stark", "Sansa": "Stark", "Jon": "Stark", "Cersei": "Lannister", "Jaime": "Lannister", "Tyrion": "Lannister"})
  {'Stark': ['Arya', 'Sansa', 'Jon'], 'Lannister': ['Cersei', 'Jaime', 'Tyrion']}
  """
  swapped = {}
  for k, v in d.items():
    if v not in swapped:
      swapped[v] = [k]
    else:
      swapped[v].append(k)
  return swapped
doctest.run_docstring_examples(swap_dictionary, globals())