example_Patch1 = '''
	&* class adder:
	&-- def goodbye
	&++def new_Function
	hhh
	&* def hello():
	Test Text
'''

example_Patch2 = '''
'''

example_Patch3 = '''
&* class adder:
'''

example_Patch4 = '''
&* class adder:
&-- def goodbye
&++yoo
'''

example_Patch5 = '''
HI1
&* class 
HI
'''

example_Patch6 = '''
&-- class
&++
&*def goodbye():
'''

example_Patch7 = '''
&-- def goodbye
&+
'''

example_Patch8 = '''
&-- class adder
&++mass
&* def hello
&*return goodbye "Hello"
'''

example_Patch9 = '''
&-- def goodbye
&++def new_function
'''

example_Patch10 = '''
&-- return goodbye "Hello"
&++def new_function
&* ggg
'''

example_Patch11 = '''
&-- print("Say
&++def new_function
&* class
'''

example_Patch12 = '''
&-- "Say goodbye"
&++"Say hello"
au revoir
'''

example_Patch13 = '''
&*class adder:
&*	def goodbye():
&*		print("Say goodbye")
&*class ader:
&*	def hello():
&*		return goodbye "Hello"
'''

example_Patch14 = '''
Hola
&*class adder:
&*	def goodbye():
&*		print("Say goodbye")
&*class ader:
&*	def hello():
&*		return goodbye
Au revoir
'''

example_Patch15 = '''
&--
&++
'''

example_Patch16 = '''
&--class adder:
&++
&--	def goodbye():
&++
&--		print("Say goodbye")
&++
&--class ader:
&++
&--	def hello():
&++
&--		return goodbye "Hello"
&++
'''

example_Patch17 = '''
Hello
&--class adder:
&++
&--	def goodbye():
&++
&--		print("Say goodbye")
&++
&--class ader:
&++
&--	def hello():
&++
&--		return goodbye "Hello"
&++
Hello
'''

example_Patch18 = '''
&* class adder: def goodbye
def new_function():
'''

example_Patch19 = '''
&-- class adder: def goodbye
&++Insert newline1
&* class ader:def hello()
Insert newline2
'''

example_Patch20 = '''
&-- class adder: def goodbye
&++Insert newline1
&* class ader:def hello():return goodbye "Hello"
Insert newline2
'''

example_Patch21 = '''
&-- class adder: def goodbye(): print("Say goodbye") class ader: def hello(): return goodbye "Hello"
&++
'''

example_Patch22 = '''
Hi
&-- class adder: def goodbye(): print("Say goodbye") class ader: def hello(): return goodbye "Hello"
&++
Hi
'''
