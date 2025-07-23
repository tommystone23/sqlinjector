# SQLInjector
SQLInjector is a plugin that uses the SQLMap API to provide SQLInjection scanning to PTT.
SQLMap comes bundled with this plugin and will run the API server automatically on startup.

The SQLMap API is a RESTful based server that will execute SQLMap scans. The API server is running on port 9200.

## Installation

Create a python venv:
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
pyinstaller --add-data="sqlinjector/templates:templates" --add-data="sqlinjector/sqlmap.zip:." --onefile --name sqlinjector.plugin sqlinjector/main.py
```

The resulting binary `./dist/sqlinjector.plugin` can be copied over to the PTT plugins directory for use.