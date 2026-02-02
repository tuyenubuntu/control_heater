#include <Wire.h> 
#include "LiquidCrystal_I2C.h"
#include <EEPROM.h>

// ================= CẤU HÌNH PHẦN CỨNG =================
LiquidCrystal_I2C lcd(0x27, 16, 2); 

// Chân kết nối
const int BUZZER_PIN = 2;  // Còi báo
const int HEATER_PIN = 3;  // Đèn Heating
const int FAN_PIN = 5;     // Quạt Cooling

// Cấu hình
const int FAN_MAX_PWM = 250; // Quạt chạy tối đa mức 250 khi quá nhiệt/tản nhiệt
const float MAX_TEMP_SET = 65.0; // Giới hạn nhiệt độ
const int MAX_TIMER_SET = 9;     // Giới hạn phút timer

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

void loop() {
  currentMillis = millis(); 

  handleEncoderUpdate();
  handleButtonPress();

  if (currentMillis - lastTempRead >= TEMP_INTERVAL) {
    lastTempRead = currentMillis;
    float temp = readThermocouple();
    if (!isnan(temp)) {
      temperature_read = temp;
    }
  }

  if (menu_activated == 1) {
    runControlLogic();
  } else {
    // Trong MENU: Tắt hết để an toàn
    analogWrite(HEATER_PIN, 255); 
    digitalWrite(FAN_PIN, LOW);   
    digitalWrite(BUZZER_PIN, LOW);
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
    analogWrite(HEATER_PIN, 255);       // Tắt đèn
    analogWrite(FAN_PIN, FAN_MAX_PWM); // Quạt BẬT mạnh để hạ nhiệt
    
    // Buzzer kêu chu kỳ 5 giây (1s Kêu - 4s Tắt)
    if (buzzer_enabled) {
        if ((currentMillis % 5000) < 1000) digitalWrite(BUZZER_PIN, HIGH);
        else digitalWrite(BUZZER_PIN, LOW);
    }
    PID_value = 0;
  } 
  else if (timer_finished) {
    // --- DONE (HẾT GIỜ) ---
    analogWrite(HEATER_PIN, 255);      // Tắt nhiệt
    analogWrite(FAN_PIN, FAN_MAX_PWM); // BẬT QUẠT tản nhiệt sau khi nấu xong
    
    // Kêu tít tít nhanh báo hiệu xong
    if ((currentMillis / 500) % 2 == 0) digitalWrite(BUZZER_PIN, HIGH);
    else digitalWrite(BUZZER_PIN, LOW);
  } 
  else {
    // --- RUNNING ---
    digitalWrite(BUZZER_PIN, LOW);  
    digitalWrite(FAN_PIN, LOW); // Tắt quạt khi đang gia nhiệt bình thường

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
      
      analogWrite(HEATER_PIN, 255 - PID_value); 
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
      // Căn giữa: "  OVERHEATED!   "
      lcd.print("  OVERHEATED!   ");
    }
    else if (timer_finished) {
      // Căn giữa: " DONE! COOLING  " (Báo cooling vì quạt đang chạy)
      lcd.print(" DONE! COOLING  ");
    }
    else {
      // 1. Hiển thị % Công suất (Vị trí 0-5)
      lcd.setCursor(0, 1);
      int p_percent = (PID_value / 255.0) * 100;
      lcd.print("P:"); 
      if(p_percent < 100) lcd.print(" ");
      if(p_percent < 10) lcd.print(" ");
      lcd.print(p_percent);
      lcd.print("%");

      // 2. Hiển thị Thanh Công suất (Vị trí 6-10: 5 ô)
      lcd.setCursor(6, 1);
      int bars = map(PID_value, 0, 255, 0, 5); 
      for (int i = 0; i < 5; i++) {
          if (i < bars) lcd.write(255); 
          else lcd.print(" ");          
      }

      // 3. Hiển thị Timer (Vị trí 11-15: Sát phải)
      lcd.setCursor(11, 1);
      if (is_timer_running) {
        unsigned long elapsed = currentMillis - timer_start_millis;
        unsigned long remaining_ms = ((unsigned long)timer_minutes_setting * 60000UL) - elapsed;
        int remaining_min = (remaining_ms + 59000) / 60000;
        
        // Căn chỉnh sát phải
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
  
  // --- CHỈNH SỬA LOGIC GIỚI HẠN VÀ XOAY VÒNG ---

  if (menu_activated == 2) { // Set Nhiệt độ
      set_temperature += (change * 0.5);
      // Logic xoay vòng 0-65
      if (set_temperature > MAX_TEMP_SET) set_temperature = 0.0;
      else if (set_temperature < 0.0) set_temperature = MAX_TEMP_SET;
  }
  else if (menu_activated == 3) kp += change;
  else if (menu_activated == 4) ki += change;
  else if (menu_activated == 5) kd += change;
  else if (menu_activated == 6) { // Set Timer
      timer_minutes_setting += change;
      // Logic xoay vòng 0-9
      if (timer_minutes_setting > MAX_TIMER_SET) timer_minutes_setting = 0;
      else if (timer_minutes_setting < 0) timer_minutes_setting = MAX_TIMER_SET;
  }
  else if (menu_activated == 7) buzzer_enabled = !buzzer_enabled;
  
  encoder_diff = 0;
}

void handleButtonPress() {
  if (button_pressed_flag) {
    if (millis() - last_button_press > 200) { 
      
      // Reset khi Overheat hoặc Done
      if (menu_activated == 1 && (timer_finished)) {
          timer_finished = false;
          timer_minutes_setting = 0;
          is_timer_running = false;
          last_button_press = millis();
          button_pressed_flag = false;
          // Khi reset xong, quạt sẽ tự tắt ở vòng loop kế tiếp (trong khối else của runControlLogic)
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
    // Kiểm tra thêm điều kiện temp <= 65 khi load từ EEPROM
    if (!isnan(temp) && temp >= 0 && temp <= MAX_TEMP_SET) {
        set_temperature = temp;
        EEPROM.get(ADDR_KP, kp);
        EEPROM.get(ADDR_KI, ki);
        EEPROM.get(ADDR_KD, kd);
        EEPROM.get(ADDR_BUZZER, buzzer_enabled);
    } else {
        // Nếu EEPROM rác hoặc > 65, reset về mặc định
        set_temperature = 37.0;
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