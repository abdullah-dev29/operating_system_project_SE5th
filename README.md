# **Deadlock Simulator – Interactive Resource Allocation Graph Visualizer & Analyzer**

This is our **Operating Systems Semester Project (Fall 2025)**.
We (Abdullah, Mutahar, and Ameer) developed a simple and interactive **Deadlock Simulator** that helps students understand OS concepts like resource allocation, RAGs, deadlock, safe state, unsafe state, and recovery.

The purpose of this project is to make hard OS concepts easier by showing them visually through a GUI.

## **What This Project Does (Simple Explanation)**

This simulator allows you to:

* Create processes and resources
* Allocate and release resources
* Make processes request resources
* Detect deadlocks using graph cycle detection
* Check safe/unsafe states using **Banker’s Algorithm**
* Visualize a complete **Resource Allocation Graph (RAG)**
* Load test scenarios (Deadlock, Safe, Unsafe, Multi-Instance)
* Approve pending requests
* View system statistics
* Export logs and reports

Everything is visual so OS concepts are easy to understand.


## **Who Made This Project**

* **Abdullah – 62724**
* **Muhammad Mutahar – 63513**
* **Ameer Hamza – 65260**

Instructor: **Dr. Jan**
BUITEMS – Department of Software Engineering


## **Requirements & Dependencies**

### **Python Version**

* Python **3.8+**

### **Install Dependencies**

```bash
pip install networkx matplotlib
```

Tkinter comes built-in with most Python versions.

## **How to Run the Project**

```bash
git clone https://github.com/abdullah-dev29/operating_system_project_SE5th
cd operating_system_project_SE5th
python gui.py
```

The application window will open automatically.


## **Included Test Scenarios**

* **Deadlock Scenario**
* **Safe State Scenario**
* **Unsafe State Scenario**
* **Multi-Instance Scenario**

## **Reports & Statistics (NEW)**

Our simulator provides built-in tools for exporting and analyzing system behavior:

### **Export Log**

Saves the entire activity log of allocations, requests, releases, and checks in a `.txt` file.

### **Export Report (JSON)**

Exports a full snapshot of the system, including:

* Current processes
* Current resources
* Resource instance counts
* Pending requests
* Deadlock status
* Safety check status
* Statistics summary

This is useful for instructors or evaluators verifying the results.

### **View System Statistics**

Shows real-time Stats:

* Total Requests
* Total Allocations
* Total Releases
* Deadlocks Detected
* Safety Checks
* Recovery Actions
* Active Processes
* Active Resources
* Pending Requests
* Total Graph Edges

This reflects the internal OS-style functioning of the simulator.

## **Project Structure**

```
allocation.py      -> Core OS logic (allocation, deadlock detection, safety)
visualization.py   -> Draws the RAG using NetworkX + Matplotlib
gui.py             -> Tkinter interface (controls, scenarios, reports)
```


## **Purpose of This Project**

The main goal of this project is to help OS students:

* Understand how deadlocks actually form
* Visualize process–resource dependencies
* Learn safe vs unsafe states interactively
* See multi-instance resource handling
* Practice OS concepts in a hands-on environment

## **License**

This project is open for educational and academic use.
