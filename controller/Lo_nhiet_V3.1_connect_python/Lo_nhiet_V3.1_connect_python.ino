#include <Wire.h> 
#include "LiquidCrystal_I2C.h"
#include <EEPROM.h>

// ================= CẤU HÌNH PHẦN CỨNG =================
LiquidCrystal_I2C lcd(0x27, 16, 2); 

const int BUZZER_PIN = 2;  
const int HEATER_PIN = 3;  
const int FAN_PIN = 5;     

// --- GIỚI HẠN AN TOÀN ---
const int FAN_MAX_PWM = 250; 
const float ABSOLUTE_MAX_TEMP = 65.0; // Giới hạn cứng
const float OVERHEAT_MARGIN = 5.0;    // Vượt SP 5 độ là báo động
const int MAX_TIMER_SET = 9;          // Max 9 phút

// MAX6675 Pins
#define MAX6675_CS   10
#define MAX6675_SO   12
#define MAX6675_SCK  13

// ================= BIẾN HỆ THỐNG =================
unsigned long currentMillis = 0;
unsigned long lastLCDUpdate = 0;
unsigned long lastTempRead = 0;
const int LCD_INTERVAL = 300;   
const int TEMP_INTERVAL = 200; // Đọc nhanh để lấy mẫu cho bộ lọc

// ================= SERIAL PROTOCOL (Python <-> Arduino) =================
// Lưu ý: KHÔNG thay đổi logic cũ. Phần này chỉ "bổ sung" để PC/Python có thể:
// - gửi lệnh set SP/PID/MODE/START/STOP/MAN
// - nhận telemetry dạng key=value theo chu kỳ
const unsigned long TELEMETRY_INTERVAL = 250; // ms
unsigned long lastTelemetrySend = 0;

// Remote control flags (mặc định giữ nguyên hành vi cũ)
bool remote_stop = false;        // STOP từ PC -> tắt output (an toàn)
bool remote_manual = false;      // MODE=MANUAL -> dùng output manual từ PC
int manual_heater_pct = 0;       // 0..100
int manual_fan_pct = 0;          // 0..100

// Sensor health (để báo ALARM=SENSOR khi thermocouple lỗi)
bool sensor_ok = true;

// Buffer nhận lệnh Serial (non-blocking)
const int SERIAL_BUF_LEN = 80;
char serial_buf[SERIAL_BUF_LEN];
uint8_t serial_buf_pos = 0;

// Prototype bổ sung
void handleSerial();
void processCommand(char* line);
void sendTelemetryLine();

// PID Var
float set_temperature = 37.0; 
float temperature_read = 0.0; // Biến này sẽ lưu giá trị ĐÃ ĐƯỢC LÀM MỊN
float PID_error = 0, previous_error = 0;
float PID_out = 0; 
int kp = 90, ki = 30, kd = 80; 
float PID_p = 0, PID_i = 0, PID_d = 0;
unsigned long lastPIDTime = 0;

// Timer
int timer_minutes_setting = 0;       
unsigned long timer_start_millis = 0;
unsigned long timer_finish_timestamp = 0; 
bool is_timer_running = false;
bool timer_finished = false;

// Trạng thái hoạt động
bool is_emergency = false;      
bool is_cooling_state = false;  
bool last_cooling_state = false; 
bool buzzer_enabled = true;
int control_mode = 0; // 0: STD, 1: DUAL

// Menu & Encoder
int menu_activated = 1; 
volatile int encoder_diff = 0; 
volatile bool button_pressed_flag = false;
unsigned long last_button_press = 0;
unsigned long last_interaction_time = 0;

// EEPROM
const int ADDR_SET_TEMP = 0;
const int ADDR_KP = 10;
const int ADDR_KI = 14;
const int ADDR_KD = 18;
const int ADDR_BUZZER = 26;
const int ADDR_MODE = 30;

// Prototype
void runControlLogic();
void updateLCD();
void printCentered(int row, String text);
void handleEncoderUpdate();
void handleButtonPress();
void saveSettings();
void loadSettings();
double readThermocouple();
void beepShort(); 

// ================= SETUP =================
void setup() {
  Serial.begin(9600); 
  
  pinMode(FAN_PIN, OUTPUT);
  pinMode(HEATER_PIN, OUTPUT);
  pinMode(BUZZER_PIN, OUTPUT);
  pinMode(MAX6675_CS, OUTPUT);
  pinMode(MAX6675_SO, INPUT);
  pinMode(MAX6675_SCK, OUTPUT);
  
  digitalWrite(FAN_PIN, LOW); 
  analogWrite(HEATER_PIN, 255); 
  digitalWrite(BUZZER_PIN, LOW);

  TCCR2B = (TCCR2B & 0b11111000) | 0x03; 

  pinMode(8, INPUT); 
  pinMode(9, INPUT); 
  pinMode(11, INPUT_PULLUP); 

  PCICR |= (1 << PCIE0);
  PCMSK0 |= (1 << PCINT0);
  PCMSK0 |= (1 << PCINT1);
  PCMSK0 |= (1 << PCINT3);

  lcd.init();
  lcd.backlight();
  
  loadSettings(); 
  timer_minutes_setting = 0; 
  
  printCentered(0, "SYSTEM STARTED");
  delay(1000);
  lcd.clear();
}

// ================= LOOP =================
void loop() {
  currentMillis = millis(); 

  handleSerial();

  handleEncoderUpdate();
  handleButtonPress();

  // Auto Exit Menu
  if (menu_activated != 1 && (currentMillis - last_interaction_time > 10000)) {
     menu_activated = 1; 
     lcd.clear();
  }

  // --- ĐỌC NHIỆT ĐỘ VÀ LỌC NHIỄU (Smoothing) ---
  if (currentMillis - lastTempRead >= TEMP_INTERVAL) {
    lastTempRead = currentMillis;
    float raw_temp = readThermocouple(); // Đọc giá trị thô
    
    if (!isnan(raw_temp)) {
      sensor_ok = true;
      // BỘ LỌC THÔNG THẤP (Low Pass Filter)
      // Giúp đường đồ thị mượt mà hơn, loại bỏ gai nhiễu
      if (temperature_read == 0) {
        temperature_read = raw_temp;
      } else {
        temperature_read = (temperature_read * 0.70) + (raw_temp * 0.30);
      }
    } else {
      sensor_ok = false;
    }
  }

  // Điều khiển
  if (menu_activated == 1) {
    runControlLogic();
  } else {
    analogWrite(HEATER_PIN, 255); 
    digitalWrite(FAN_PIN, LOW);   
    digitalWrite(BUZZER_PIN, LOW);
  }

  // Telemetry cho Python/GUI
  if (currentMillis - lastTelemetrySend >= TELEMETRY_INTERVAL) {
    lastTelemetrySend = currentMillis;
    sendTelemetryLine();
  }

  // Hiển thị
  if (currentMillis - lastLCDUpdate >= LCD_INTERVAL) {
    lastLCDUpdate = currentMillis;
    updateLCD();
  }
}

// ================= LOGIC ĐIỀU KHIỂN =================
void runControlLogic() {

  // 0. REMOTE STOP (từ PC) - ưu tiên an toàn, không ảnh hưởng logic khi không dùng
  if (remote_stop) {
      analogWrite(HEATER_PIN, 255);  // heater OFF (active LOW)
      analogWrite(FAN_PIN, 0);       // fan OFF
      digitalWrite(BUZZER_PIN, LOW);
      PID_i = 0;

      // Giữ output Plotter như cũ (Power=0)
      Serial.print("SetPoint:"); Serial.print(set_temperature);
      Serial.print(",ProcessValue:"); Serial.print(temperature_read);
      Serial.println(",Power:0");
      return;
  }

  
  // 1. KIỂM TRA AN TOÀN (EMERGENCY)
  if (temperature_read >= ABSOLUTE_MAX_TEMP || temperature_read >= (set_temperature + OVERHEAT_MARGIN)) {
      is_emergency = true;
      analogWrite(HEATER_PIN, 255); 
      analogWrite(FAN_PIN, FAN_MAX_PWM); 
      
      if (currentMillis % 1000 < 500) digitalWrite(BUZZER_PIN, HIGH);
      else digitalWrite(BUZZER_PIN, LOW);
      
      PID_i = 0; 
      
      // Plotter output báo lỗi
      Serial.print("SetPoint:"); Serial.print(set_temperature);
      Serial.print(",ProcessValue:"); Serial.print(temperature_read);
      Serial.println(",Power:0");
      
      return; 
  } else {
      is_emergency = false;
  }

  // 2. KIỂM TRA TIMER
  if (is_timer_running) {
    if (currentMillis - timer_start_millis >= (unsigned long)timer_minutes_setting * 60000UL) {
       is_timer_running = false;
       timer_finished = true;
       timer_finish_timestamp = currentMillis;
       timer_minutes_setting = 0; 
    }
  }

  // 3. TRẠNG THÁI: DONE
  if (timer_finished) {
    analogWrite(HEATER_PIN, 255);      
    analogWrite(FAN_PIN, FAN_MAX_PWM); 
    
    if (currentMillis - timer_finish_timestamp < 5000) {
        if ((currentMillis / 200) % 2 == 0) digitalWrite(BUZZER_PIN, HIGH);
        else digitalWrite(BUZZER_PIN, LOW);
    } else {
        digitalWrite(BUZZER_PIN, LOW); 
    }
    
    // Plotter output
    Serial.print("SetPoint:"); Serial.print(set_temperature);
    Serial.print(",ProcessValue:"); Serial.print(temperature_read);
    Serial.println(",Power:0");
    return;
  }


  // 3.5. REMOTE MANUAL OUTPUT (từ PC) - chỉ khi MODE=MANUAL
  // Vẫn giữ các lớp bảo vệ (emergency/timer_done đã return ở trên)
  if (remote_manual) {
    digitalWrite(BUZZER_PIN, LOW);

    int heater_pwm = map(manual_heater_pct, 0, 100, 0, 255);
    int fan_pwm    = map(manual_fan_pct,    0, 100, 0, FAN_MAX_PWM);

    analogWrite(HEATER_PIN, 255 - heater_pwm); // active LOW
    analogWrite(FAN_PIN, fan_pwm);

    // Plotter output (giữ format cũ)
    Serial.print("SetPoint:"); Serial.print(set_temperature);
    Serial.print(",ProcessValue:"); Serial.print(temperature_read);
    Serial.print(",Power:"); Serial.println(heater_pwm);

    return;
  }

  // 4. CHẠY PID
  digitalWrite(BUZZER_PIN, LOW);

  unsigned long timeChange = (currentMillis - lastPIDTime);
  if (timeChange >= 100) { 
    float dt = timeChange / 1000.0;
    PID_error = set_temperature - temperature_read;
    
    PID_p = 0.01 * kp * PID_error;
    PID_i += (ki * PID_error * dt * 0.01);
    
    if (PID_i > 255) PID_i = 255;
    if (PID_i < -255) PID_i = -255;

    PID_d = 0.01 * kd * ((PID_error - previous_error) / dt);
    
    float raw_output = PID_p + PID_i + PID_d;
    
    // ================= XỬ LÝ MODE =================
    if (control_mode == 0) { // STD MODE
        
        // Hysteresis logic
        if (temperature_read > set_temperature) is_cooling_state = true;
        else if (temperature_read < set_temperature - 2.0) is_cooling_state = false;

        // Báo hiệu chuyển trạng thái
        if (is_cooling_state != last_cooling_state) {
            beepShort(); 
            last_cooling_state = is_cooling_state; 
        }

        if (is_cooling_state) {
            PID_out = 0; 
            analogWrite(HEATER_PIN, 255);
            analogWrite(FAN_PIN, FAN_MAX_PWM); 
            PID_i = 0; 
        } else {
            if (raw_output < 0) raw_output = 0;
            if (raw_output > 255) raw_output = 255;
            PID_out = raw_output;
            
            analogWrite(HEATER_PIN, 255 - (int)PID_out);
            digitalWrite(FAN_PIN, LOW);
        }
    } 
    else { // DUAL MODE
        if (raw_output > 255) raw_output = 255;
        if (raw_output < -255) raw_output = -255;
        PID_out = raw_output;

        if (raw_output > 0) {
            analogWrite(HEATER_PIN, 255 - (int)raw_output);
            digitalWrite(FAN_PIN, LOW);
        } else {
            analogWrite(HEATER_PIN, 255); 
            int fan_speed = abs((int)raw_output);
            if (fan_speed > 0 && fan_speed < 50) fan_speed = 50; 
            analogWrite(FAN_PIN, fan_speed);
        }
    }

    // ================= IN RA SERIAL PLOTTER =================
    Serial.print("SetPoint:"); 
    Serial.print(set_temperature);
    Serial.print(",ProcessValue:"); 
    Serial.print(temperature_read);
    Serial.print(",Power:"); 
    Serial.println(abs(PID_out));
    // ========================================================

    previous_error = PID_error;
    lastPIDTime = currentMillis;
  }
}

void beepShort() {
    if (buzzer_enabled) {
        digitalWrite(BUZZER_PIN, HIGH);
        delay(50); 
        digitalWrite(BUZZER_PIN, LOW);
    }
}

// ================= HIỂN THỊ LCD =================
void updateLCD() {
  String header = "SP:" + String(set_temperature, 1) + "  PV:" + String(temperature_read, 1);
  printCentered(0, header);

  if (menu_activated != 1) {
    String menuText = "";
    switch (menu_activated) {
      case 2: menuText = "Set SP: " + String(set_temperature, 1); break;
      case 3: menuText = "Set Kp: " + String(kp); break;
      case 4: menuText = "Set Ki: " + String(ki); break;
      case 5: menuText = "Set Kd: " + String(kd); break;
      case 6: menuText = "Timer: " + String(timer_minutes_setting) + "m"; break;
      case 7: menuText = "Buzzer: " + String(buzzer_enabled ? "ON" : "OFF"); break;
      case 8: menuText = "Mode: " + String(control_mode == 0 ? "STD" : "DUAL"); break; 
    }
    printCentered(1, menuText);
  } 
  else {
    if (is_emergency) {
       printCentered(1, "!! OVERHEAT !!"); 
    }
    else if (timer_finished) {
       printCentered(1, "DONE! COOLING");
    }
    else if (control_mode == 0 && is_cooling_state) {
       printCentered(1, "COOLING (STD)...");
    }
    else {
      lcd.setCursor(0, 1);
      
      if (PID_out >= 0) lcd.print("H:"); 
      else lcd.print("F:"); 
      
      int val_display = abs((int)PID_out);
      int p_percent = (val_display / 255.0) * 100;
      
      if(p_percent < 100) lcd.print(" "); 
      if(p_percent < 10) lcd.print(" ");
      lcd.print(p_percent);
      lcd.print("% "); 

      int bars = map(val_display, 0, 255, 0, 4); 
      for (int i = 0; i < 4; i++) {
          if (i < bars) lcd.write(255); 
          else lcd.print("-");         
      }
      lcd.print(" ");

      if (is_timer_running) {
        unsigned long elapsed = currentMillis - timer_start_millis;
        unsigned long remaining_ms = ((unsigned long)timer_minutes_setting * 60000UL) - elapsed;
        int remaining_min = (remaining_ms + 59000) / 60000;
        
        lcd.print("T"); 
        if(remaining_min < 10) lcd.print(remaining_min);
        else lcd.print("9"); 
      } else {
        lcd.print("T-"); 
      }
    }
  }
}

void printCentered(int row, String text) {
  int len = text.length();
  if (len > 16) len = 16; 
  int padding = (16 - len) / 2;
  lcd.setCursor(0, row);
  for(int i=0; i<padding; i++) lcd.print(" ");
  lcd.print(text);
  for(int i=0; i<(16 - len - padding); i++) lcd.print(" ");
}

// ================= INPUT (ENCODER) =================
void handleEncoderUpdate() {
  if (encoder_diff == 0) return;
  last_interaction_time = millis(); 
  float change = encoder_diff;
  
  if (menu_activated == 2) { 
      set_temperature += (change * 0.5);
      if (set_temperature > ABSOLUTE_MAX_TEMP) set_temperature = 0.0;
      else if (set_temperature < 0.0) set_temperature = ABSOLUTE_MAX_TEMP;
  }
  else if (menu_activated == 3) kp += change;
  else if (menu_activated == 4) ki += change;
  else if (menu_activated == 5) kd += change;
  else if (menu_activated == 6) { 
      timer_minutes_setting += change;
      if (timer_minutes_setting > MAX_TIMER_SET) timer_minutes_setting = 0;
      else if (timer_minutes_setting < 0) timer_minutes_setting = MAX_TIMER_SET;
  }
  else if (menu_activated == 7) buzzer_enabled = !buzzer_enabled;
  else if (menu_activated == 8) { 
      control_mode += change;
      if (control_mode > 1) control_mode = 0;
      if (control_mode < 0) control_mode = 1;
  }
  
  encoder_diff = 0;
}

void handleButtonPress() {
  if (button_pressed_flag) {
    last_interaction_time = millis(); 

    if (millis() - last_button_press > 200) { 
      
      beepShort(); 

      if (menu_activated == 1 && (timer_finished || is_emergency)) {
          timer_finished = false;
          is_emergency = false;
          timer_minutes_setting = 0;
          is_timer_running = false;
          last_button_press = millis();
          button_pressed_flag = false;
          return;
      }

      if (menu_activated == 8) { 
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

void saveSettings() {
    EEPROM.put(ADDR_SET_TEMP, set_temperature);
    EEPROM.put(ADDR_KP, kp);
    EEPROM.put(ADDR_KI, ki);
    EEPROM.put(ADDR_KD, kd);
    EEPROM.put(ADDR_BUZZER, buzzer_enabled);
    EEPROM.put(ADDR_MODE, control_mode);
    lcd.clear();
    printCentered(0, "SETTINGS SAVED");
    delay(500); 
}

void loadSettings() {
    float temp;
    EEPROM.get(ADDR_SET_TEMP, temp);
    if (!isnan(temp) && temp >= 0 && temp <= ABSOLUTE_MAX_TEMP) {
        set_temperature = temp;
        EEPROM.get(ADDR_KP, kp);
        EEPROM.get(ADDR_KI, ki);
        EEPROM.get(ADDR_KD, kd);
        EEPROM.get(ADDR_BUZZER, buzzer_enabled);
        EEPROM.get(ADDR_MODE, control_mode);
        if(control_mode < 0 || control_mode > 1) control_mode = 0;
    } else {
        set_temperature = 37.0;
        control_mode = 0;
    }
}

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

// ================= SERIAL HANDLER & TELEMETRY =================
void handleSerial() {
  while (Serial.available() > 0) {
    char c = (char)Serial.read();

    // bỏ CR
    if (c == '\r') continue;

    if (c == '\n') {
      if (serial_buf_pos == 0) continue;
      serial_buf[serial_buf_pos] = '\0';
      processCommand(serial_buf);
      serial_buf_pos = 0;
      continue;
    }

    // chống tràn buffer
    if (serial_buf_pos < SERIAL_BUF_LEN - 1) {
      serial_buf[serial_buf_pos++] = c;
    } else {
      // nếu quá dài -> reset buffer
      serial_buf_pos = 0;
    }
  }
}

static float _toFloatOrNaN(const char* s) {
  if (!s) return NAN;
  return atof(s);
}

static int _toIntClamp(const char* s, int lo, int hi) {
  if (!s) return lo;
  int v = atoi(s);
  if (v < lo) v = lo;
  if (v > hi) v = hi;
  return v;
}

// Parse command theo protocol trong Python:
//   SP=45.0
//   PID,KP=90,KI=30,KD=80
//   MODE=AUTO / MODE=MANUAL
//   START / STOP
//   MAN,H=50,F=20
void processCommand(char* line) {
  // trim whitespace
  while (*line == ' ' || *line == '\t') line++;
  if (*line == '\0') return;

  // Uppercase copy cho phần keyword
  // (vẫn giữ line gốc để parse giá trị số)
  String s = String(line);
  s.trim();

  // ===== START/STOP =====
  if (s.equalsIgnoreCase("START")) {
    remote_stop = false;
    return;
  }
  if (s.equalsIgnoreCase("STOP")) {
    remote_stop = true;
    return;
  }

  // ===== SP= =====
  if (s.startsWith("SP=") || s.startsWith("sp=")) {
    int eq = s.indexOf('=');
    float sp = s.substring(eq + 1).toFloat();
    if (sp < 0) sp = 0;
    if (sp > ABSOLUTE_MAX_TEMP) sp = ABSOLUTE_MAX_TEMP;
    set_temperature = sp;
    return;
  }

  // ===== MODE= =====
  if (s.startsWith("MODE=") || s.startsWith("mode=")) {
    int eq = s.indexOf('=');
    String mv = s.substring(eq + 1);
    mv.trim();
    mv.toUpperCase();

    if (mv == "MANUAL") remote_manual = true;
    else if (mv == "AUTO") remote_manual = false;

    // Bonus: cho phép set mode cũ STD/DUAL qua Serial
    if (mv == "STD") control_mode = 0;
    else if (mv == "DUAL") control_mode = 1;

    return;
  }

  // ===== PID, KP/KI/KD =====
  if (s.startsWith("PID") || s.startsWith("pid")) {
    // Tách theo dấu phẩy
    // Ví dụ: PID,KP=90.000,KI=30.000,KD=80.000
    int p1 = 0;
    while (true) {
      int comma = s.indexOf(',', p1);
      String token = (comma == -1) ? s.substring(p1) : s.substring(p1, comma);
      token.trim();

      int eq = token.indexOf('=');
      if (eq > 0) {
        String k = token.substring(0, eq);
        String v = token.substring(eq + 1);
        k.trim(); k.toUpperCase();
        v.trim();

        if (k == "KP") kp = (int)round(v.toFloat());
        else if (k == "KI") ki = (int)round(v.toFloat());
        else if (k == "KD") kd = (int)round(v.toFloat());
      }

      if (comma == -1) break;
      p1 = comma + 1;
    }
    return;
  }

  // ===== MAN,H=xx,F=yy =====
  if (s.startsWith("MAN") || s.startsWith("man")) {
    int p1 = 0;
    while (true) {
      int comma = s.indexOf(',', p1);
      String token = (comma == -1) ? s.substring(p1) : s.substring(p1, comma);
      token.trim();

      int eq = token.indexOf('=');
      if (eq > 0) {
        String k = token.substring(0, eq);
        String v = token.substring(eq + 1);
        k.trim(); k.toUpperCase();
        v.trim();

        if (k == "H") manual_heater_pct = constrain((int)round(v.toFloat()), 0, 100);
        else if (k == "F") manual_fan_pct = constrain((int)round(v.toFloat()), 0, 100);
      }

      if (comma == -1) break;
      p1 = comma + 1;
    }
    return;
  }

  // (Optional) REQ -> gửi telemetry ngay
  if (s.equalsIgnoreCase("REQ")) {
    sendTelemetryLine();
    return;
  }
}

void sendTelemetryLine() {
  // Tính % heater/fan đang điều khiển (ước lượng theo logic hiện tại)
  int heater_pct = 0;
  int fan_pct = 0;

  if (menu_activated != 1) {
    heater_pct = 0;
    fan_pct = 0;
  } else if (is_emergency) {
    heater_pct = 0;
    fan_pct = 100;
  } else if (timer_finished) {
    heater_pct = 0;
    fan_pct = 100;
  } else if (remote_stop) {
    heater_pct = 0;
    fan_pct = 0;
  } else if (remote_manual) {
    heater_pct = manual_heater_pct;
    fan_pct = manual_fan_pct;
  } else {
    // AUTO: dựa trên PID_out + control_mode
    if (control_mode == 0) { // STD
      if (is_cooling_state) {
        heater_pct = 0;
        fan_pct = 100;
      } else {
        heater_pct = (int)round((abs(PID_out) / 255.0) * 100.0);
        fan_pct = 0;
      }
    } else { // DUAL
      if (PID_out > 0) {
        heater_pct = (int)round((abs(PID_out) / 255.0) * 100.0);
        fan_pct = 0;
      } else if (PID_out < 0) {
        heater_pct = 0;
        fan_pct = (int)round((abs(PID_out) / 255.0) * 100.0);

        // fan min 50 PWM trong code -> phản ánh tối thiểu ~ (50/FAN_MAX_PWM)
        if (fan_pct > 0) {
          int minPct = (int)round((50.0 / FAN_MAX_PWM) * 100.0);
          if (fan_pct < minPct) fan_pct = minPct;
        }
      } else {
        heater_pct = 0;
        fan_pct = 0;
      }
    }
  }

  float pv = temperature_read;
  float sp = set_temperature;
  float err = sp - pv;

  String mode = remote_manual ? "MANUAL" : "AUTO";

  String alarm = "NONE";
  if (!sensor_ok) alarm = "SENSOR";
  if (remote_stop) alarm = "STOP";
  if (timer_finished) alarm = "TIMER_DONE";
  if (is_emergency) alarm = "OVERTEMP"; // ưu tiên cao nhất

  // Format đúng Python parser: PV=..,SP=..,ERR=..,H=..,F=..,MODE=..,ALARM=..
  Serial.print("PV=");   Serial.print(pv, 2);
  Serial.print(",SP=");  Serial.print(sp, 2);
  Serial.print(",ERR="); Serial.print(err, 2);
  Serial.print(",H=");   Serial.print(heater_pct);
  Serial.print(",F=");   Serial.print(fan_pct);
  Serial.print(",MODE="); Serial.print(mode);
  Serial.print(",ALARM="); Serial.println(alarm);
}
