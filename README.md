# SQLInjector

## Installation

Create a python venv like:
```bash
python3 -m venv <venv_name>
```
Activate the venv:
```bash
source <venv_name>/bin/activate
```
Install dependencies:
```bash
pip install -r requirements.txt
```
Build packaged binary:
```bash
pyinstaller --add-data="sqlinjector/templates:templates" --add-data="sqlinjector/sqlmap.zip:." --onefile --name sqlinjector.plugin main.py
```

The resulting binary `./dist/sqlinjector.plugin` can be copied over to the PTT plugins directory for use.