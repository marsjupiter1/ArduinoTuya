# ArduinoTuya
library for communicating with tuya devices via the cloud

For example usage see:
https://github.com/marsjupiter1/bigbutton/blob/main/bigbutton.ino

The main thing to be aware of is that tuya needs timestamps and Arduino by default contains no real time clock.
Hence the main program needs to do an nttp sync before it can play.

The code sample is still under development, but you can see it:

1. instantiating a TuyaAuth class.
2. waiting for autorisation.
3. Asking tuya how a device works.
4. turning a device on.



