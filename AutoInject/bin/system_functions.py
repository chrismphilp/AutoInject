try:
	import httplib
except:
	import http.client as httplib

def connected_To_Internet():

	conn = httplib.HTTPConnection("www.google.com", timeout=5)
	try:
		conn.request("/HEAD", "/")
		conn.close()
		return True
	except:
		conn.close()
		return False