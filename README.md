# 🚨 Snort Intrusion Detection System (IDS) on Windows

## 📚 **Project Overview**
This project sets up an **Intrusion Detection System (IDS)** using **Snort** on a Windows environment. The IDS monitors HTTP traffic to detect common web-based attacks, such as:

- **SQL Injection**
- **Cross-Site Scripting (XSS)**
- **Directory Traversal Attacks**
- General HTTP GET requests

The project demonstrates how Snort can effectively monitor, log, and alert malicious activities on a local web server.

---

## 💻 **System Requirements**
- **Operating System:** Windows 10/11
- **Snort Version:** 2.x
- **Web Server:** Apache (via XAMPP or WAMP)
- **Browser:** Any modern browser
- **Network Adapter:** Intel Dual Band Wireless Adapter (or similar)

---

## 🛠️ **Installation & Configuration Steps**

### 1. **Install Snort**
- Download and install Snort from the [official Snort website](https://www.snort.org/downloads).
- Ensure the `snort.conf` file is properly configured.

### 2. **Setup Snort Configuration (`snort.conf`)**
- Define `HOME_NET` to match your network.
  ```plaintext
  var HOME_NET 192.168.128.0/24
  ```
- Enable HTTP inspection and preprocessors.

### 3. **Write Detection Rules**
Add the following rules to your **local.rules** file:
```plaintext
alert tcp any any -> any 80 (msg:"HTTP GET request detected"; content:"GET"; sid:1000001; rev:1;)
alert tcp any any -> any 80 (msg:"Access to index.html detected"; content:"/index.html"; sid:1000002; rev:1;)
alert tcp any any -> any 80 (msg:"SQL Injection Attempt"; content:"' OR '1'='1"; sid:1000003; rev:1;)
alert tcp any any -> any 80 (msg:"XSS Attack Attempt"; content:"<script>alert"; nocase; sid:1000004; rev:1;)
alert tcp any any -> any 80 (msg:"Directory Traversal Attempt"; content:"../../"; sid:1000005; rev:1;)
```

### 4. **Start Snort in Console Mode**
```cmd
snort -i 4 -c C:\Snort\etc\snort.conf -A console -l C:\Snort\log
```

### 5. **Test the IDS**
- Perform simulated attacks (SQL Injection, XSS) via HTTP requests.
- Verify alerts in the Snort console or log files.

---

## 📁 **Files to Include in Repository**
1. **snort.conf** – Main configuration file.
2. **local.rules** – Custom Snort rules.
3. **index.html** – Webpage for attack simulation.
4. **alert.log (example)** – Sample Snort alert log.
5. **README.md** – Documentation (this file).
6. **screenshots/** – Folder containing screenshots of alerts and setup.

---

## 📊 **Testing Examples**
- **SQL Injection:** `' OR '1'='1`
- **XSS Attack:** `<script>alert('XSS')</script>`
- **Directory Traversal:** `../../etc/passwd`

---

## 📝 **Known Issues**
- Snort may not capture traffic if the wrong network interface is selected.
- Ensure the `HOME_NET` variable matches your actual network range.

---

## 🤝 **Contributing**
Feel free to fork this repository, submit pull requests, or raise issues if you encounter any problem.

---

## 🛡️ **Disclaimer**
This project is intended for **educational purposes only**. Unauthorized testing on external servers is illegal.

---

## 📬 **Contact**
- **Author:** Shahzaib Haider 
- **Email:** malikshahzaibaps@gmail.com
- **GitHub:** https://github.com/ShahzaibHaider0

---

## ⭐ **Acknowledgments**
- **Snort Documentation**
- **Apache Server Docs**
- **Community Forums**

---

Happy Monitoring! 🚀
