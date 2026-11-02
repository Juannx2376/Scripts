# Reverse Shell

A simple automatized Reverse Shell build on Python 
(Idea project from El Pinguino de Mario)

## Requirements

- Python 3

## Usage

On the attacking device you have to run

```bash
python listener.py
```
And on the victim device

```bash
python client.py
```

client.py listens the port 8080 of the attacker IP, and the listener.py opens the connection so the client.py can connect