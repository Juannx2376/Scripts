# Steganography Tool

Hide secret text messages inside images, invisible to the eye, using **LSB (Least Significant Bit)** steganography.

Each pixel has three color channels (R, G, B), each 0–255. Changing the **last bit** of a channel shifts the color by at most 1 — imperceptible to a human — but that last bit can store one bit of a hidden message. This tool writes the message into those last bits and reads it back out.

## Features

- 🖼️ Hide any text message inside a PNG image
- 🔍 Reveal a hidden message from an image
- 🏁 End marker so the reader knows exactly where the message stops
- 🛟 Output is forced to `.png` automatically (JPEG compression would destroy the hidden bits)

## Requirements

- Python 3
- [Pillow](https://pypi.org/project/Pillow/):

```bash
pip install Pillow
```

## Usage

```bash
python esteganografia.py
```

- **Hide** → give an input image, your message, and an output name → produces a `.png` that looks identical but carries the message
- **Reveal** → give an image that contains a hidden message → prints it back

> ⚠️ Always use **PNG** for the output. JPEG re-compresses pixels when saving, which would corrupt the hidden data. The tool enforces `.png` for you.

## How it works

```
hide:    text -> bits -> written into the last bit of each R/G/B channel + end marker
reveal:  read the last bit of each channel -> rebuild bits -> stop at the marker -> text
```
