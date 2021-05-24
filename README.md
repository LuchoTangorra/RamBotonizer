# Ram botonizer

Ram botonizer is a free software that lets you see the path and ram usage of every jupyter notebook running locally (if used in a server it will show the ram usage in that server). Also, it could show the kernel ID, kernel name, kernel state, kernel connections, base url, user and pid.

It works on any operative system!

This free software is used by software agencies in Buenos Aires, Argentina.

### How to use
- Minimun requirements: python3 installed. 
- Go to the RamBotonizer path.
- Possible program args:
	- --password : password to access the jupyter notebooks.
	- --short : if true it will only show path and ram usage, otherwise it will show the full jupyter notebook info.
- Run: python3 RamBotonizer.py [--password PASSWORD] [--short true/false]
