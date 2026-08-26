SckitDecoder Android project

How to use

1) Open the project in Android Studio (File → Open) and let Gradle sync.
2) Currently the app includes the Python script at app/src/main/assets/sckit.py. The APK does not bundle a Python runtime.

Options to run the decoder from the app:

- Chaquopy (run Python inside the APK): add Chaquopy plugin to app/build.gradle and call the script from Kotlin. See Chaquopy docs: https://chaquopy.dev/

- Termux: copy the asset to app.filesDir (the app has a button to copy the asset). Then use Termux or an external mechanism to execute the Python script on-device.

Future improvements
- Fully integrate Chaquopy to run the decoder directly from the app UI.
- Display progress and parsed candidate list.
- Add support for reading/decoding DEX files in-app.
