# 🔥 PID Furnace Temperature Control System

## 📌 Overview


This project implements an **automatic furnace temperature control
system using PID control**.\
The system measures temperature in real-time, controls heater power
using PWM, and integrates safety, timer, cooling, and user interface
features.

------------------------------------------------------------------------

## 🧩 System Functional Modules

------------------------------------------------------------------------

## 🌡️ 1. Temperature Measurement & Monitoring

-   Reads temperature from **K-type thermocouple** via **MAX6675**
-   Measured temperature is used as **PV (Process Value)** for control
-   Periodic update using **non-blocking timing (millis instead of
    delay)**

**👉 Function:**\
Real-time furnace temperature monitoring.

------------------------------------------------------------------------

## 🎯 2. PID Temperature Control

-   Compares:
    -   PV → Measured temperature\
    -   SP → Setpoint temperature
-   Applies **PID algorithm (P--I--D)** to calculate:
    -   Heater power level
-   PID output converted to **PWM signal** for heater control

**👉 Function:**\
Maintain stable furnace temperature at setpoint.

------------------------------------------------------------------------

## 🔥 3. Heater Power Control

-   Heater controlled using **PWM (Active LOW)**
-   Power changes continuously based on PID output:
    -   Far from SP → Higher power
    -   Near SP → Reduced power

**👉 Function:**\
Smooth heating and overshoot reduction.

------------------------------------------------------------------------

## ⏱️ 4. Heating Timer

-   Allows configuration of heating duration
-   When time expires:
    -   Heater OFF
    -   System switches to Completed state
    -   Alarm activated

**👉 Function:**\
Automatic heating stop based on preset time.

------------------------------------------------------------------------

## 🛡️ 5. Over-Temperature Protection (Safety)

System monitors: - Temperature exceeding safety threshold

When triggered: - Heater OFF immediately - Cooling fan ON - Buzzer alarm
ON

**👉 Function:**\
Protect furnace and hardware from overheating.

------------------------------------------------------------------------

## 🌀 6. Cooling Fan Control

Fan operates based on system states (No PID control): - Over-temperature
condition - Timer finished - Post-heating cooling phase

**👉 Function:**\
Reduce temperature and protect system components.

------------------------------------------------------------------------

## 🔔 7. Buzzer Alarm System

Buzzer activates when: - Over-temperature occurs - Heating timer ends

Can be enabled/disabled via menu.

**👉 Function:**\
Provide audible system status notification.

------------------------------------------------------------------------

## 🖥️ 8. User Interface (LCD + Encoder)

### LCD I2C Displays:

-   Setpoint Temperature (SP)
-   Actual Temperature (PV)
-   Heater Power Level
-   Remaining Time

### Encoder + Push Button Controls:

-   Adjust SP
-   Adjust PID parameters (Kp, Ki, Kd)
-   Adjust Timer
-   Enable / Disable Buzzer

**👉 Function:**\
System configuration and user interaction.

------------------------------------------------------------------------

## 💾 9. Configuration Storage (EEPROM)

Stored parameters: - Setpoint temperature - PID parameters (Kp, Ki,
Kd) - Buzzer state

Configuration retained after power loss.

**👉 Function:**\
Improve system usability and stability.

------------------------------------------------------------------------

## ⚡ 10. Real-Time Non-Blocking Operation

Uses: - `millis()` instead of `delay()`

Parallel task execution: - Temperature reading - PID calculation - Timer
counting - LCD update

**👉 Function:**\
Fast response and stable real-time operation.

------------------------------------------------------------------------

## 🛠️ Technologies Used

-   Arduino Platform\
-   MAX6675 Thermocouple Interface\
-   PID Control Algorithm\
-   PWM Heater Control\
-   EEPROM Storage\
-   LCD I2C Interface\
-   Rotary Encoder Input

------------------------------------------------------------------------

## 📈 Key System Advantages

✅ Real-time temperature control\
✅ Stable PID regulation\
✅ Integrated safety protection\
✅ User-friendly interface\
✅ Non-blocking real-time execution\
✅ Configuration persistence

------------------------------------------------------------------------

## 🖼️ Screenshots

Below are screenshots and UI samples from the `ui/images` folder to help visualize the application.

- Control / Monitoring UI

    ![Control UI](ui/images/Screenshot%202026-02-07%20015417.png)

- Demo screen 1

    ![Demo 1](ui/images/demo_%201.png)

- Demo screen 2

    ![Demo 2](ui/images/demo_%202.png)

- Demo screen 3

    ![Demo 3](ui/images/demo_%203.png)

- Example line chart

    ![Line chart sample](ui/images/line.jpg)

    ------------------------------------------------------------------------

    Copyright: © 2026 tuyenubuntu


