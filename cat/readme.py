"""

# Stack exploitation: `cat.exe`

## Preparations

### .. Tools

* [Notepad++](https://notepad-plus-plus.org)
* [Immunity Debugger](https://www.Immunityinc.com/products/debugger/)
* [Mona.py](https://github.com/corelan/mona) (Place the mona script in the PyCommands folder of Immunity Debugger)
* [MsfVenom](https://www.offensive-security.com/metasploit-unleashed/msfvenom/)
  (Part of Kali Linux)
* [Python 2.7](https://www.python.org)
* "Optional" ***Use a Virtual Machine***

### .. Setup

* Place the _cat.exe_ sample in a folder
* Set the workingfolder for _mona_ `!mona config -set workingdirectory C:\path\to\sample` (Enter this command in the textbox, in the bottom, of _Immunity_.)

"""

# This script generates the README.md file...

import re

files = [
	"readme.py", 
	"fuzz1.py",
	"fuzz2.py",
	"fuzz3.py",
	"fuzz4.py",
	"fuzz5.py",
	"exploit.py"
]

with open('readme.md', 'w') as output:
	for index in range(0, len(files)):
		with open(files[index], 'r') as input:
			content = input.read()
			output.write(re.search("\"\"\"([.\s\S]*)\"\"\"", content).group(1).strip())
			output.write('\r\n')
			if index > 0:
				output.write('### .. Code for `' + files[index] + '`\r\n```python\r\n')
				output.write(re.search("\"\"\"[.\s\S]*\"\"\"([.\s\S]*)", content).group(1).strip())
				output.write('\r\n```\r\n')
			output.write('---\r\n')
