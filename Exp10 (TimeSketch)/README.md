# 🧪 Experiment 10: Incident Reconstruction using Logs

## 🎯 Objective

To analyze system and network logs and reconstruct a sequence of events to simulate a digital forensic investigation.

---

## 🛠 Tools Used

* System Logs (journalctl / log files)
* Timesketch (optional)

---

## ⚙️ Procedure

### Step 1: Collect System Logs

```bash
journalctl > logs.txt
```

---

### Step 2: Identify Relevant Events

Analyze logs for:

* Login activities
* File access
* System errors
* Network connections

---

### Step 3: Filter Important Entries

```bash
grep "login" logs.txt
grep "error" logs.txt
```

---

### Step 4: Arrange Events Chronologically

* Sort events by timestamp
* Identify sequence of actions

---

### Step 5: Reconstruct Incident

* Determine what happened
* Identify suspicious activities
* Link events together

---

### Step 6: (Optional) Use Timesketch

* Upload logs
* Visualize timeline
* Correlate events

---

## 📸 Screenshots

![Logs Output](screenshots/logs.png)
![Filtered Logs](screenshots/filter.png)

---

## 📊 Result

System logs were successfully analyzed and a sequence of events was reconstructed, identifying potential suspicious activities.

---

## 🧠 Conclusion

Log analysis helps investigators reconstruct incidents and understand system behavior during an event.

---
