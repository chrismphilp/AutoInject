import AutoInject.bin.build_From_Source 	as bfs
import AutoInject.bin.testing.test_patches 	as tp
import unittest

class test_Build_From_Source(unittest.TestCase):

	def setUp(self):
		self.lexer_for_addition = bfs.lexer_for_addition

	def return_tuples(self, addition_string):
		self.lexer_for_addition.input(addition_string)
		return bfs.get_Tuples_For_Addition(
			'../../file_store/test/test2.py', 
			self.lexer_for_addition, 
			addition_string
		)

	def test_Basic_Patch(self):
		self.assertEqual(
			self.return_tuples(tp.example_Patch1), 
			[(14, 25, 'def new_Function'), (28, '\thhh'), (78, '\tTest Text')]
		)

	def test_Empty_Input(self):
		self.assertFalse(
			self.return_tuples(tp.example_Patch2)
		)

	def test_Just_Context(self):
		self.assertFalse(
			self.return_tuples(tp.example_Patch3)
		)

	def test_Basic_Replacement(self):
		self.assertEqual(
			self.return_tuples(tp.example_Patch4), 
			[(14, 25, 'yoo')]
		)

	def test_Basic_Context_Insertion(self):
		self.assertEqual(
			self.return_tuples(tp.example_Patch5), 
			[(0, 'HI1'), (12, 'HI')]
		)

	def test_Partial_Replacement_With_Context(self):
		self.assertEqual(
			self.return_tuples(tp.example_Patch6), 
			[(0, 5, '')]
		)

	def test_Broken_Replacement(self):
		self.assertFalse(
			self.return_tuples(tp.example_Patch7)
		)

	def test_Replacement_And_Context(self):
		self.assertEqual(
			self.return_tuples(tp.example_Patch8), 
			[(0, 11, 'mass')]
		)

	def test_Partial_Function_Replacement(self):
		self.assertEqual(
			self.return_tuples(tp.example_Patch9), 
			[(14, 25, 'def new_function')]
		)

	def test_Partial_Function_Replacement_Then_Failed_Context(self):
		self.assertFalse(
			self.return_tuples(tp.example_Patch10)
		)

	def test_Failed_Replacement(self):
		self.assertFalse(
			self.return_tuples(tp.example_Patch11)
		)

	def test_Partial_Function_Replacement(self):
		self.assertEqual(
			self.return_tuples(tp.example_Patch12), 
			[(37, 50, '"Say hello"'), (51, 'au revoir')]
		)

	def test_Full_Context(self):
		self.assertFalse(
			self.return_tuples(tp.example_Patch13)
		)

	def test_Partial_Function_Replacement(self):
		self.assertEqual(
			self.return_tuples(tp.example_Patch14), 
			[(0, 'Hola'), (103, 'Au revoir')]
		)

	def test_Empty_Replacement(self):
		self.assertFalse(
			self.return_tuples(tp.example_Patch15)
		)

	def test_Full_Replacement(self):
		self.assertEqual(
			self.return_tuples(tp.example_Patch16), 
			[(0, 12, ''), (14, 28, ''), (31, 51, ''), (53, 64, ''), (66, 78, ''), (81, 103, '')]
		)

	def test_Full_Replacement_With_Insertion_At_Start_And_End(self):
		self.assertEqual(
			self.return_tuples(tp.example_Patch17), 
			[(0, 'Hello'), (0, 12, ''), (14, 28, ''), (31, 51, ''), (53, 64, ''), (66, 78, ''), (81, 103, ''), (103, 'Hello')]
		)

	def test_Multiline_Context(self):
		self.assertEqual(
			self.return_tuples(tp.example_Patch18), 
			[(28, 'def new_function():')]
		)

	def test_Multiline_Replacement_With_Context(self):
		self.assertEqual(
			self.return_tuples(tp.example_Patch19), 
			[(0, 25, 'Insert newline1'), (78, 'Insert newline2')]
		)

	def test_Multiline_Replacement_With_Context_And_Insertion(self):
		self.assertEqual(
			self.return_tuples(tp.example_Patch20), 
			[(0, 25, 'Insert newline1'), (103, 'Insert newline2')]
		)

	def test_Full_One_Line_Replacement(self):
		self.assertEqual(
			self.return_tuples(tp.example_Patch21), 
			[(0, 103, '')]
		)

	def test_Full_One_Line_Replacement_With_Insertions(self):
		self.assertEqual(
			self.return_tuples(tp.example_Patch22), 
			[(0, 'Hi'), (0, 103, ''), (103, 'Hi')]
		)

if __name__ == '__main__':
	unittest.main()