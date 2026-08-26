# Sckit-Android

This repository contains an Android Studio project (Kotlin + Jetpack Compose) named SckitDecoder.

Purpose
- Provide a small Android front-end that includes your Python decoder script as an asset (app/src/main/assets/sckit.py).
- UI includes a paste textbox, file picker for APK/DEX, a Decode button (placeholder), and results list UI.

Notes
- The project does NOT bundle a Python runtime. The Python script is included as an asset so you can later integrate it using Chaquopy (run Python inside the APK) or call Termux/Termux:API to execute the script on-device.
- See README.md for instructions on how to use Chaquopy or Termux to run the script.
