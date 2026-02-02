#include <Wire.h> 
#include "LiquidCrystal_I2C.h"
#include <EEPROM.h>

// ================= CẤU HÌNH PHẦN CỨNG =================
LiquidCrystal_I2C lcd(0x27, 16, 2); 

// Chân kết nối
const int BUZZER_PIN = 2;  // Còi báo
const int HEATER_PIN = 3;  // Đèn Heating (Active LOW)
const int FAN_PIN = 5;     // Quạt Cooling

// Cấu hình
const int FAN_MAX_PWM = 250;       // Quạt chạy tối đa mức 250 khi quá nhiệt/tản nhiệt
const float MAX_TEMP_SET = 65.0;   // Giới hạn nhiệt độ
const int MAX_TIMER_SET = 9;       // Giới hạn phút timer

// MAX6675 Pins
#define MAX6675_CS   10
#define MAX6675_SO   12
#define MAX6675_SCK  13

// ================= BIẾN TOÀN CỤC =================
unsigned long currentMillis = 0;
unsigned long lastLCDUpdate = 0;
unsigned long lastTempRead = 0;
const int LCD_INTERVAL = 300;   
const int TEMP_INTERVAL = 500;  

// Nhiệt độ & PID
float set_temperature = 37.0; 
float temperature_read = 0.0;
float PID_error = 0, previous_error = 0;
float PID_value = 0;
int kp = 90, ki = 30, kd = 80; 
float PID_p = 0, PID_i = 0, PID_d = 0;
unsigned long lastPIDTime = 0;

// Timer & Logic trạng thái
int timer_minutes_setting = 0;       
unsigned long timer_start_millis = 0;
bool is_timer_running = false;
bool timer_finished = false;
bool buzzer_enabled = true;
bool is_overheated = false;

// Menu & Encoder
int menu_activated = 1; 
volatile int encoder_diff = 0; 
volatile bool button_pressed_flag = false;
unsigned long last_button_press = 0;

// EEPROM Addresses
const int ADDR_SET_TEMP = 0;
const int ADDR_KP = 10;
const int ADDR_KI = 14;
const int ADDR_KD = 18;
const int ADDR_BUZZER = 26;

// ================= SERIAL PROTOCOL (PC <-> Arduino) =================
// Baud hiện tại là 9600 (khớp code bạn đang có). Nếu muốn nhanh hơn đổi cả Python + Arduino lên 115200.
unsigned long lastTelemetryMs = 0;
const unsigned long TELEMETRY_INTERVAL = 300; // ms

bool pc_run_enabled = true; // START/STOP từ PC (mặc định true để không phá behavior cũ)

enum ControlMode { MODE_AUTO, MODE_MANUAL };
ControlMode pc_mode = MODE_AUTO;

// Manual outputs khi MODE=MANUAL
int manual_heater_pct = 0; // 0..100
int manual_fan_pct = 0;    // 0..100

// Tracking output để gửi lên PC
int heater_pwm_out = 0; // 0..255 (PID_value)
int fan_pwm_out = 0;    // 0..255

bool sensor_ok = true;  // sensor lỗi => ALARM=SENSOR

// ================== FORWARD DECLARATIONS ==================
void applyHeaterPWM(int pwm255);
void applyFanPWM(int pwm255);
void handleSerial();
void sendTelemetry();

// ================== SETUP ==================
void setup() {
  Serial.begin(9600);
  
  pinMode(FAN_PIN, OUTPUT);
  pinMode(HEATER_PIN, OUTPUT);
  pinMode(BUZZER_PIN, OUTPUT);
  pinMode(MAX6675_CS, OUTPUT);
  pinMode(MAX6675_SO, INPUT);
  pinMode(MAX6675_SCK, OUTPUT);
  
  digitalWrite(FAN_PIN, LOW); 
  analogWrite(HEATER_PIN, 255); // Tắt đèn (Active Low)
  digitalWrite(BUZZER_PIN, LOW);

  // Tăng tần số PWM cho êm (Pin 3 & 11)
  TCCR2B = (TCCR2B & 0b11111000) | 0x03;

  pinMode(8, INPUT); // CLK
  pinMode(9, INPUT); // DT
  pinMode(11, INPUT_PULLUP); // SW

  PCICR |= (1 << PCIE0);
  PCMSK0 |= (1 << PCINT0);
  PCMSK0 |= (1 << PCINT1);
  PCMSK0 |= (1 << PCINT3);

  lcd.init();
  lcd.backlight();
  
  loadSettings(); 
  timer_minutes_setting = 0; 
  
  lcd.setCursor(0, 0); lcd.print(" SYSTEM STARTED ");
  delay(1000);
  lcd.clear();
}

// ================== LOOP ==================
void loop() {
  currentMillis = millis(); 

  // Serial protocol
  handleSerial();
  sendTelemetry();

  handleEncoderUpdate();
  handleButtonPress();

  if (currentMillis - lastTempRead >= TEMP_INTERVAL) {
    lastTempRead = currentMillis;
    float temp = readThermocouple();
    if (!isnan(temp)) {
      temperature_read = temp;
      sensor_ok = true;
    } else {
      sensor_ok = false;
    }
  }

  // Ưu tiên an toàn trong MENU
  if (menu_activated != 1) {
    // Trong MENU: Tắt hết để an toàn
    applyHeaterPWM(0);
    applyFanPWM(0);
    digitalWrite(BUZZER_PIN, LOW);
  } else {
    // MAIN screen: cho phép PC điều khiển mode + start/stop
    if (!pc_run_enabled) {
      // STOP từ PC
      applyHeaterPWM(0);
      applyFanPWM(0);
      digitalWrite(BUZZER_PIN, LOW);
      // không reset menu/timer để bạn vẫn thao tác được
    }
    else if (pc_mode == MODE_MANUAL) {
      // MANUAL từ PC: set output theo %
      int h_pwm = (int)round(manual_heater_pct * 255.0 / 100.0);
      int f_pwm = (int)round(manual_fan_pct * 255.0 / 100.0);
      applyHeaterPWM(h_pwm);
      applyFanPWM(f_pwm);
      digitalWrite(BUZZER_PIN, LOW);
    }
    else {
      // AUTO: giữ nguyên logic điều khiển cũ
      runControlLogic();
    }
  }

  if (currentMillis - lastLCDUpdate >= LCD_INTERVAL) {
    lastLCDUpdate = currentMillis;
    updateLCD();
  }
}

// ================= LOGIC VẬN HÀNH =================
void runControlLogic() {
  // 1. Timer Logic
  if (is_timer_running) {
    unsigned long elapsed = currentMillis - timer_start_millis;
    if (elapsed >= (unsigned long)timer_minutes_setting * 60000UL) {
       is_timer_running = false;
       timer_finished = true;
       timer_minutes_setting = 0; 
    }
  }

  // 2. Overheat Check
  if (!is_overheated && set_temperature > 0 && temperature_read >= (set_temperature + 3.0)) {
    is_overheated = true;
  }
  else if (is_overheated && temperature_read < set_temperature) {
    is_overheated = false;
  }

  // 3. Output Control
  if (is_overheated) {
    // --- OVERHEATED ---
    applyHeaterPWM(0);                 // Tắt đèn
    applyFanPWM(FAN_MAX_PWM);          // Quạt mạnh để hạ nhiệt
    
    // Buzzer kêu chu kỳ 5 giây (1s Kêu - 4s Tắt)
    if (buzzer_enabled) {
      if ((currentMillis % 5000) < 1000) digitalWrite(BUZZER_PIN, HIGH);
      else digitalWrite(BUZZER_PIN, LOW);
    }
    PID_value = 0;
  } 
  else if (timer_finished) {
    // --- DONE (HẾT GIỜ) ---
    applyHeaterPWM(0);                 // Tắt nhiệt
    applyFanPWM(FAN_MAX_PWM);          // BẬT QUẠT tản nhiệt
    
    // Kêu tít tít nhanh báo hiệu xong
    if ((currentMillis / 500) % 2 == 0) digitalWrite(BUZZER_PIN, HIGH);
    else digitalWrite(BUZZER_PIN, LOW);
  } 
  else {
    // --- RUNNING ---
    digitalWrite(BUZZER_PIN, LOW);  
    applyFanPWM(0); // Tắt quạt khi đang gia nhiệt bình thường

    unsigned long timeChange = (currentMillis - lastPIDTime);
    if (timeChange >= 100) { 
      float dt = timeChange / 1000.0;
      PID_error = set_temperature - temperature_read;
      PID_p = 0.01 * kp * PID_error;
      PID_i += (ki * PID_error * dt * 0.01);
      PID_d = 0.01 * kd * ((PID_error - previous_error) / dt);
      
      PID_value = PID_p + PID_i + PID_d;
      if (PID_value < 0) PID_value = 0;
      if (PID_value > 255) PID_value = 255;

      applyHeaterPWM((int)PID_value); // track output + active low inside function

      previous_error = PID_error;
      lastPIDTime = currentMillis;
    }
  }
}

// ================= GIAO DIỆN LCD (UPDATE) =================
void updateLCD() {
  lcd.setCursor(0, 0);
  lcd.print("SP:"); lcd.print(set_temperature, 1);
  lcd.print(" PV:"); lcd.print(temperature_read, 1);

  lcd.setCursor(0, 1);
  if (menu_activated != 1) {
    // --- MENU ---
    switch (menu_activated) {
      case 2: lcd.print("Set SP: "); lcd.print(set_temperature, 1); break;
      case 3: lcd.print("Set Kp: "); lcd.print(kp); break;
      case 4: lcd.print("Set Ki: "); lcd.print(ki); break;
      case 5: lcd.print("Set Kd: "); lcd.print(kd); break;
      case 6: lcd.print("Timer:  "); lcd.print(timer_minutes_setting); lcd.print("m"); break;
      case 7: lcd.print("Buzzer: "); lcd.print(buzzer_enabled ? "ON " : "OFF"); break;
    }
    lcd.print("      "); 
  } 
  else {
    // --- MAIN SCREEN ---
    if (is_overheated) {
      lcd.print("  OVERHEATED!   ");
    }
    else if (timer_finished) {
      lcd.print(" DONE! COOLING  ");
    }
    else {
      lcd.setCursor(0, 1);
      int p_percent = (PID_value / 255.0) * 100;
      lcd.print("P:"); 
      if(p_percent < 100) lcd.print(" ");
      if(p_percent < 10) lcd.print(" ");
      lcd.print(p_percent);
      lcd.print("%");

      lcd.setCursor(6, 1);
      int bars = map(PID_value, 0, 255, 0, 5); 
      for (int i = 0; i < 5; i++) {
        if (i < bars) lcd.write(255); 
        else lcd.print(" ");          
      }

      lcd.setCursor(11, 1);
      if (is_timer_running) {
        unsigned long elapsed = currentMillis - timer_start_millis;
        unsigned long remaining_ms = ((unsigned long)timer_minutes_setting * 60000UL) - elapsed;
        int remaining_min = (remaining_ms + 59000) / 60000;
        
        if (remaining_min < 10) lcd.print(" T: ");   
        else lcd.print(" T:");                        

        lcd.print(remaining_min);
        lcd.print("m");
      } else {
        lcd.print(" T:0m"); 
      }
    }
  }
}

// ================= INPUT (ENCODER/BUTTON) =================
void handleEncoderUpdate() {
  if (encoder_diff == 0) return;
  float change = encoder_diff;

  if (menu_activated == 2) { // Set Nhiệt độ
    set_temperature += (change * 0.5);
    if (set_temperature > MAX_TEMP_SET) set_temperature = 0.0;
    else if (set_temperature < 0.0) set_temperature = MAX_TEMP_SET;
  }
  else if (menu_activated == 3) kp += change;
  else if (menu_activated == 4) ki += change;
  else if (menu_activated == 5) kd += change;
  else if (menu_activated == 6) { // Set Timer
    timer_minutes_setting += change;
    if (timer_minutes_setting > MAX_TIMER_SET) timer_minutes_setting = 0;
    else if (timer_minutes_setting < 0) timer_minutes_setting = MAX_TIMER_SET;
  }
  else if (menu_activated == 7) buzzer_enabled = !buzzer_enabled;

  encoder_diff = 0;
}

void handleButtonPress() {
  if (button_pressed_flag) {
    if (millis() - last_button_press > 200) { 
      
      if (menu_activated == 1 && (timer_finished)) {
        timer_finished = false;
        timer_minutes_setting = 0;
        is_timer_running = false;
        last_button_press = millis();
        button_pressed_flag = false;
        return;
      }

      if (menu_activated == 7) { 
        saveSettings(); 
        menu_activated = 1; 
        
        if (timer_minutes_setting > 0) {
          is_timer_running = true;
          timer_start_millis = currentMillis; 
          timer_finished = false;
        } else {
          is_timer_running = false;
          timer_finished = false;
        }
      } else {
        menu_activated++;
      }
      last_button_press = millis();
      lcd.clear(); 
    }
    button_pressed_flag = false;
  }
}

ISR(PCINT0_vect) {
  static unsigned long last_interrupt_time = 0;
  unsigned long interrupt_time = millis();
  
  if (interrupt_time - last_interrupt_time > 5) { 
    uint8_t pin_state = PINB;
    int clk_state = (pin_state & 0x01); 
    int dt_state  = (pin_state & 0x02) >> 1; 
    static int last_clk_state = 0;

    if (clk_state != last_clk_state && clk_state == 1) {
      if (dt_state != clk_state) encoder_diff = 1; 
      else encoder_diff = -1; 
    }
    last_clk_state = clk_state;

    if ((pin_state & 0x08) == 0) button_pressed_flag = true;
  }
  last_interrupt_time = interrupt_time;
}

// ================= EEPROM =================
void saveSettings() {
  EEPROM.put(ADDR_SET_TEMP, set_temperature);
  EEPROM.put(ADDR_KP, kp);
  EEPROM.put(ADDR_KI, ki);
  EEPROM.put(ADDR_KD, kd);
  EEPROM.put(ADDR_BUZZER, buzzer_enabled);
  lcd.clear();
  lcd.setCursor(0,0); lcd.print(" SETTING SAVED! ");
  delay(500); 
}

void loadSettings() {
  float temp;
  EEPROM.get(ADDR_SET_TEMP, temp);
  if (!isnan(temp) && temp >= 0 && temp <= MAX_TEMP_SET) {
    set_temperature = temp;
    EEPROM.get(ADDR_KP, kp);
    EEPROM.get(ADDR_KI, ki);
    EEPROM.get(ADDR_KD, kd);
    EEPROM.get(ADDR_BUZZER, buzzer_enabled);
  } else {
    set_temperature = 37.0;
  }
}

// ================= MAX6675 =================
double readThermocouple() {
  uint16_t v;
  digitalWrite(MAX6675_CS, LOW);
  v = shiftIn(MAX6675_SO, MAX6675_SCK, MSBFIRST);
  v <<= 8;
  v |= shiftIn(MAX6675_SO, MAX6675_SCK, MSBFIRST);
  digitalWrite(MAX6675_CS, HIGH);
  if (v & 0x4) return NAN;
  v >>= 3;
  return v * 0.25;
}

// ================= SERIAL HELPERS =================
void applyHeaterPWM(int pwm255) {
  pwm255 = constrain(pwm255, 0, 255);
  heater_pwm_out = pwm255;
  analogWrite(HEATER_PIN, 255 - pwm255); // Active LOW
}

void applyFanPWM(int pwm255) {
  pwm255 = constrain(pwm255, 0, 255);
  fan_pwm_out = pwm255;
  analogWrite(FAN_PIN, pwm255);
}

void handleSerial() {
  static String rx = "";

  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\r') continue;

    if (c == '\n') {
      rx.trim();
      if (rx.length() > 0) {
        if (rx == "START") {
          pc_run_enabled = true;
          // không reset PID_i để tránh giật
        }
        else if (rx == "STOP") {
          pc_run_enabled = false;
          is_timer_running = false;
          timer_finished = false;
          digitalWrite(BUZZER_PIN, LOW);
          applyFanPWM(0);
          applyHeaterPWM(0);
        }
        else if (rx.startsWith("MODE=")) {
          String m = rx.substring(5);
          m.trim(); m.toUpperCase();
          if (m == "AUTO") pc_mode = MODE_AUTO;
          else if (m == "MANUAL") pc_mode = MODE_MANUAL;
        }
        else if (rx.startsWith("SP=")) {
          float sp = rx.substring(3).toFloat();
          set_temperature = constrain(sp, 0.0, MAX_TEMP_SET);
        }
        else if (rx.startsWith("KP=")) {
          kp = rx.substring(3).toInt();
        }
        else if (rx.startsWith("KI=")) {
          ki = rx.substring(3).toInt();
        }
        else if (rx.startsWith("KD=")) {
          kd = rx.substring(3).toInt();
        }
        else if (rx.startsWith("PID,")) {
          // PID,KP=90,KI=30,KD=80
          int p1 = rx.indexOf("KP=");
          int p2 = rx.indexOf("KI=");
          int p3 = rx.indexOf("KD=");
          if (p1 >= 0) kp = rx.substring(p1 + 3).toInt();
          if (p2 >= 0) ki = rx.substring(p2 + 3).toInt();
          if (p3 >= 0) kd = rx.substring(p3 + 3).toInt();
        }
        else if (rx.startsWith("MAN,")) {
          // MAN,H=30,F=20
          int h = -1, f = -1;
          int ph = rx.indexOf("H=");
          int pf = rx.indexOf("F=");
          if (ph >= 0) h = rx.substring(ph + 2).toInt();
          if (pf >= 0) f = rx.substring(pf + 2).toInt();
          if (h >= 0) manual_heater_pct = constrain(h, 0, 100);
          if (f >= 0) manual_fan_pct = constrain(f, 0, 100);
        }
      }
      rx = "";
    } else {
      if (rx.length() < 140) rx += c; // tránh tràn
    }
  }
}

void sendTelemetry() {
  if (millis() - lastTelemetryMs < TELEMETRY_INTERVAL) return;
  lastTelemetryMs = millis();

  float pv = temperature_read;
  float sp = set_temperature;
  float err = sp - pv;

  int heater_pct = (int)round((heater_pwm_out / 255.0) * 100.0);
  int fan_pct = (int)round((fan_pwm_out / 255.0) * 100.0);

  String modeStr = (pc_mode == MODE_AUTO) ? "AUTO" : "MANUAL";

  String alarm = "NONE";
  if (!sensor_ok) alarm = "SENSOR";
  else if (is_overheated) alarm = "OVERTEMP";
  else if (timer_finished) alarm = "TIMERDONE";

  Serial.print("PV="); Serial.print(pv, 2);
  Serial.print(",SP="); Serial.print(sp, 2);
  Serial.print(",ERR="); Serial.print(err, 2);
  Serial.print(",H="); Serial.print(heater_pct);
  Serial.print(",F="); Serial.print(fan_pct);
  Serial.print(",MODE="); Serial.print(modeStr);
  Serial.print(",ALARM="); Serial.println(alarm);
}
