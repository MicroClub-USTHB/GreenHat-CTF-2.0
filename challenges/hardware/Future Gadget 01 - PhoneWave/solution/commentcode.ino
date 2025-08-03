#include <Adafruit_GFX.h>
#include <Adafruit_ILI9341.h>

#define TFT_CS   15
#define TFT_DC   2
#define TFT_RST  -1

Adafruit_ILI9341 d(15, 2);

String _combine(int a[], int l, int k) {
  String s = "";
  for (int i = 0; i < l; i++) {
    s += (char)(a[i] ^ k);
  }
  return s;
}

void setup() {
  d.begin();
  d.setRotation(1);
  d.fillScreen(ILI9341_BLACK);
  d.setTextSize(2);
  d.setTextColor(ILI9341_GREEN);
  d.setCursor(10, 20);

  // Corrected part1 to produce "ghctf" when XORed with 13
  int part1[] = { 'j', 'e', 'n', 'y', 'k' }; // XOR with 13 → "ghctf"
  String f1 = "";
  for (int i = 0; i < 5; i++) {
    f1 += (char)(part1[i] ^ 13);
  }

  // Corrected core to produce "TuTuRu" when XORed with 0x26
  int core[] = { 114, 83, 114, 83, 116, 83 };
  String mid = _combine(core, 6, 0x26);

  // Corrected tail to produce "U_f1x3d" when XORed with 0x3F
  int tail[] = { 106, 96, 89, 14, 71, 12, 91 }; // Direct ASCII values
  String f2 = _combine(tail, 7, 0x3F); // Use 7 elements

  String flag = f1 + "{" + mid + "_" + f2 + "_17}";
  d.println(flag);
}

void loop() {}
