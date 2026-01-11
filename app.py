import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import seaborn as sns
import hashlib
import re
import os
from datetime import datetime
import pickle

class SecurityAnalysisTool:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Advanced Security Analysis Tool")
        self.root.geometry("1400x900")
        self.root.configure(bg="#1e1e2e")
        
        # Initialize models
        self.spam_model = None
        self.malware_model = None
        self.spam_vectorizer = None
        self.malware_vectorizer = None
        
        # Statistics
        self.stats = {
            'spam_detected': 0,
            'malware_detected': 0,
            'files_scanned': 0,
            'emails_scanned': 0
        }
        
        self.setup_ui()
        self.train_initial_models()
        
    def setup_ui(self):
        # Style configuration
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background='#1e1e2e', borderwidth=0)
        style.configure('TNotebook.Tab', background='#313244', foreground='#cdd6f4', 
                       padding=[20, 10], font=('Arial', 10, 'bold'))
        style.map('TNotebook.Tab', background=[('selected', '#45475a')], 
                 foreground=[('selected', '#89b4fa')])
        
        # Main container
        main_container = tk.Frame(self.root, bg="#1e1e2e")
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        header = tk.Frame(main_container, bg="#313244", height=80)
        header.pack(fill=tk.X, pady=(0, 10))
        header.pack_propagate(False)
        
        title = tk.Label(header, text="🛡️ Security Defense System", 
                        font=("Arial", 24, "bold"), bg="#313244", fg="#89b4fa")
        title.pack(pady=20)
        
        # Notebook for tabs
        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.create_spam_tab()
        self.create_malware_tab()
        self.create_training_tab()
        self.create_statistics_tab()
        
    def create_spam_tab(self):
        spam_frame = tk.Frame(self.notebook, bg="#1e1e2e")
        self.notebook.add(spam_frame, text="📧 Spam Detection")
        
        # Left panel - Input
        left_panel = tk.Frame(spam_frame, bg="#1e1e2e")
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        tk.Label(left_panel, text="Email Content Analysis", font=("Arial", 16, "bold"),
                bg="#1e1e2e", fg="#cdd6f4").pack(anchor=tk.W, pady=(0, 10))
        
        tk.Label(left_panel, text="Enter email text to analyze:", 
                bg="#1e1e2e", fg="#a6adc8").pack(anchor=tk.W)
        
        self.spam_input = scrolledtext.ScrolledText(left_panel, height=15, 
                                                    font=("Consolas", 10),
                                                    bg="#313244", fg="#cdd6f4",
                                                    insertbackground="#cdd6f4")
        self.spam_input.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Buttons
        btn_frame = tk.Frame(left_panel, bg="#1e1e2e")
        btn_frame.pack(fill=tk.X, pady=10)
        
        tk.Button(btn_frame, text="🔍 Analyze Email", command=self.analyze_spam,
                 bg="#89b4fa", fg="#1e1e2e", font=("Arial", 12, "bold"),
                 cursor="hand2", relief=tk.FLAT, padx=20, pady=10).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="📋 Load Sample", command=self.load_sample_spam,
                 bg="#45475a", fg="#cdd6f4", font=("Arial", 12, "bold"),
                 cursor="hand2", relief=tk.FLAT, padx=20, pady=10).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="🗑️ Clear", command=lambda: self.spam_input.delete(1.0, tk.END),
                 bg="#f38ba8", fg="#1e1e2e", font=("Arial", 12, "bold"),
                 cursor="hand2", relief=tk.FLAT, padx=20, pady=10).pack(side=tk.LEFT, padx=5)
        
        # Right panel - Results
        right_panel = tk.Frame(spam_frame, bg="#1e1e2e", width=500)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, padx=10, pady=10)
        right_panel.pack_propagate(False)
        
        tk.Label(right_panel, text="Analysis Results", font=("Arial", 16, "bold"),
                bg="#1e1e2e", fg="#cdd6f4").pack(anchor=tk.W, pady=(0, 10))
        
        self.spam_result = scrolledtext.ScrolledText(right_panel, height=20,
                                                     font=("Consolas", 10),
                                                     bg="#313244", fg="#cdd6f4",
                                                     state=tk.DISABLED)
        self.spam_result.pack(fill=tk.BOTH, expand=True)
        
    def create_malware_tab(self):
        malware_frame = tk.Frame(self.notebook, bg="#1e1e2e")
        self.notebook.add(malware_frame, text="🦠 Malware Detection")
        
        # Left panel
        left_panel = tk.Frame(malware_frame, bg="#1e1e2e")
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        tk.Label(left_panel, text="File Behavior Analysis", font=("Arial", 16, "bold"),
                bg="#1e1e2e", fg="#cdd6f4").pack(anchor=tk.W, pady=(0, 10))
        
        # File selection
        file_frame = tk.Frame(left_panel, bg="#313244")
        file_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(file_frame, text="Selected File:", bg="#313244", 
                fg="#a6adc8", font=("Arial", 10)).pack(side=tk.LEFT, padx=10)
        
        self.selected_file_label = tk.Label(file_frame, text="No file selected", 
                                           bg="#313244", fg="#f9e2af", 
                                           font=("Arial", 10, "italic"))
        self.selected_file_label.pack(side=tk.LEFT, padx=10)
        
        tk.Button(file_frame, text="📁 Browse", command=self.browse_file,
                 bg="#89b4fa", fg="#1e1e2e", font=("Arial", 10, "bold"),
                 cursor="hand2", relief=tk.FLAT).pack(side=tk.RIGHT, padx=10, pady=5)
        
        # File content preview
        tk.Label(left_panel, text="File Content Preview:", 
                bg="#1e1e2e", fg="#a6adc8").pack(anchor=tk.W, pady=(10, 5))
        
        self.file_preview = scrolledtext.ScrolledText(left_panel, height=12,
                                                      font=("Consolas", 9),
                                                      bg="#313244", fg="#cdd6f4",
                                                      state=tk.DISABLED)
        self.file_preview.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Scan button
        tk.Button(left_panel, text="🔍 Scan for Malware", command=self.scan_malware,
                 bg="#a6e3a1", fg="#1e1e2e", font=("Arial", 14, "bold"),
                 cursor="hand2", relief=tk.FLAT, padx=30, pady=15).pack(pady=10)
        
        # Right panel - Results
        right_panel = tk.Frame(malware_frame, bg="#1e1e2e", width=500)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, padx=10, pady=10)
        right_panel.pack_propagate(False)
        
        tk.Label(right_panel, text="Scan Results", font=("Arial", 16, "bold"),
                bg="#1e1e2e", fg="#cdd6f4").pack(anchor=tk.W, pady=(0, 10))
        
        self.malware_result = scrolledtext.ScrolledText(right_panel, height=20,
                                                        font=("Consolas", 10),
                                                        bg="#313244", fg="#cdd6f4",
                                                        state=tk.DISABLED)
        self.malware_result.pack(fill=tk.BOTH, expand=True)
        
    def create_training_tab(self):
        training_frame = tk.Frame(self.notebook, bg="#1e1e2e")
        self.notebook.add(training_frame, text="🧠 Model Training")
        
        # Header
        tk.Label(training_frame, text="Machine Learning Model Training", 
                font=("Arial", 18, "bold"), bg="#1e1e2e", fg="#cdd6f4").pack(pady=20)
        
        # Training info
        info_frame = tk.Frame(training_frame, bg="#313244")
        info_frame.pack(fill=tk.X, padx=20, pady=10)
        
        info_text = """
        🎯 Current Models:
        • Spam Detection: Multinomial Naive Bayes with TF-IDF vectorization
        • Malware Detection: Random Forest with behavioral feature extraction
        
        📊 Features Used:
        • Linear Algebra: TF-IDF matrix operations, feature vectors
        • Probability: Naive Bayes probability calculations
        • Statistics: Feature importance, classification metrics
        """
        
        tk.Label(info_frame, text=info_text, bg="#313244", fg="#a6adc8",
                font=("Consolas", 10), justify=tk.LEFT).pack(padx=20, pady=20)
        
        # Training controls
        control_frame = tk.Frame(training_frame, bg="#1e1e2e")
        control_frame.pack(pady=20)
        
        tk.Button(control_frame, text="🔄 Retrain Spam Model", 
                 command=self.retrain_spam_model,
                 bg="#89b4fa", fg="#1e1e2e", font=("Arial", 12, "bold"),
                 cursor="hand2", relief=tk.FLAT, padx=30, pady=15).pack(pady=10)
        
        tk.Button(control_frame, text="🔄 Retrain Malware Model", 
                 command=self.retrain_malware_model,
                 bg="#a6e3a1", fg="#1e1e2e", font=("Arial", 12, "bold"),
                 cursor="hand2", relief=tk.FLAT, padx=30, pady=15).pack(pady=10)
        
        # Training log
        tk.Label(training_frame, text="Training Log:", bg="#1e1e2e", 
                fg="#cdd6f4", font=("Arial", 12, "bold")).pack(anchor=tk.W, padx=20)
        
        self.training_log = scrolledtext.ScrolledText(training_frame, height=15,
                                                      font=("Consolas", 9),
                                                      bg="#313244", fg="#cdd6f4",
                                                      state=tk.DISABLED)
        self.training_log.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
    def create_statistics_tab(self):
        stats_frame = tk.Frame(self.notebook, bg="#1e1e2e")
        self.notebook.add(stats_frame, text="📊 Statistics")
        
        # Stats header
        tk.Label(stats_frame, text="Security Analysis Statistics", 
                font=("Arial", 18, "bold"), bg="#1e1e2e", fg="#cdd6f4").pack(pady=20)
        
        # Stats display
        self.stats_frame = tk.Frame(stats_frame, bg="#1e1e2e")
        self.stats_frame.pack(fill=tk.BOTH, expand=True, padx=20)
        
        self.update_statistics_display()
        
        # Refresh button
        tk.Button(stats_frame, text="🔄 Refresh Statistics", 
                 command=self.update_statistics_display,
                 bg="#89b4fa", fg="#1e1e2e", font=("Arial", 12, "bold"),
                 cursor="hand2", relief=tk.FLAT, padx=30, pady=15).pack(pady=20)
        
    def train_initial_models(self):
        """Train models with sample data"""
        self.log_training("Initializing ML models...")
        
        # Spam detection training data
        spam_data = [
            ("Win free money now! Click here!", 1),
            ("Congratulations! You've won $1000000", 1),
            ("Get cheap viagra online", 1),
            ("Nigerian prince needs your help", 1),
            ("URGENT: Your account will be closed", 1),
            ("Free iPhone! Click now!", 1),
            ("Make money fast working from home", 1),
            ("Meeting scheduled for tomorrow at 3pm", 0),
            ("Here's the report you requested", 0),
            ("Thanks for your email, I'll get back to you", 0),
            ("Project deadline is next Friday", 0),
            ("Can we reschedule our call?", 0),
            ("Attached is the document you needed", 0),
            ("Great job on the presentation", 0),
            ("Let me know if you have any questions", 0),
            ("Your package has been shipped", 0),
            ("Reminder: Team meeting at 2pm", 0),
            ("CLICK HERE FOR AMAZING DEALS!!!", 1),
            ("You have inherited millions!", 1),
            ("Lose 20 pounds in 2 weeks!", 1),
            ("Buy now! Limited time offer!", 1),
            ("Your credit card has been charged", 1),
            ("Verify your account immediately", 1),
            ("Can you review this code?", 0),
            ("Lunch tomorrow?", 0),
            ("Happy birthday!", 0),
            ("Conference call notes attached", 0),
        ]
        
        texts, labels = zip(*spam_data)
        
        # Train spam model
        self.spam_vectorizer = TfidfVectorizer(max_features=1000)
        X_spam = self.spam_vectorizer.fit_transform(texts)
        y_spam = np.array(labels)
        
        self.spam_model = MultinomialNB()
        self.spam_model.fit(X_spam, y_spam)
        
        accuracy = accuracy_score(y_spam, self.spam_model.predict(X_spam))
        self.log_training(f"✓ Spam model trained - Accuracy: {accuracy*100:.2f}%")
        
        # Malware detection training data (simulated file features)
        malware_features = [
            # [suspicious_strings, file_entropy, api_calls, size_ratio, packed] -> label
            [15, 7.2, 45, 0.9, 1, 1],  # malware
            [12, 7.5, 50, 0.85, 1, 1],  # malware
            [2, 4.5, 10, 0.3, 0, 0],   # clean
            [1, 4.2, 8, 0.25, 0, 0],   # clean
            [20, 7.8, 60, 0.95, 1, 1], # malware
            [3, 4.8, 12, 0.35, 0, 0],  # clean
            [18, 7.4, 55, 0.88, 1, 1], # malware
            [2, 4.3, 9, 0.28, 0, 0],   # clean
            [16, 7.6, 48, 0.91, 1, 1], # malware
            [1, 4.1, 7, 0.22, 0, 0],   # clean
            [14, 7.3, 52, 0.87, 1, 1], # malware
            [3, 4.6, 11, 0.32, 0, 0],  # clean
            [19, 7.7, 58, 0.93, 1, 1], # malware
            [2, 4.4, 10, 0.29, 0, 0],  # clean
            [17, 7.5, 53, 0.89, 1, 1], # malware
        ]
        
        X_malware = np.array([f[:-1] for f in malware_features])
        y_malware = np.array([f[-1] for f in malware_features])
        
        self.malware_model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.malware_model.fit(X_malware, y_malware)
        
        accuracy = accuracy_score(y_malware, self.malware_model.predict(X_malware))
        self.log_training(f"✓ Malware model trained - Accuracy: {accuracy*100:.2f}%")
        self.log_training("✓ All models ready for detection!")
        
    def analyze_spam(self):
        """Analyze email for spam"""
        text = self.spam_input.get(1.0, tk.END).strip()
        
        if not text:
            messagebox.showwarning("Warning", "Please enter email text to analyze")
            return
        
        self.stats['emails_scanned'] += 1
        
        # Vectorize input
        X = self.spam_vectorizer.transform([text])
        
        # Predict
        prediction = self.spam_model.predict(X)[0]
        probability = self.spam_model.predict_proba(X)[0]
        
        # Feature analysis
        feature_names = self.spam_vectorizer.get_feature_names_out()
        feature_scores = X.toarray()[0]
        top_features = sorted(zip(feature_names, feature_scores), 
                            key=lambda x: x[1], reverse=True)[:10]
        
        # Spam indicators
        spam_indicators = self.detect_spam_indicators(text)
        
        # Build result
        result = f"""
{'='*60}
📧 EMAIL SPAM ANALYSIS REPORT
{'='*60}
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

🎯 CLASSIFICATION RESULT:
{'🚨 SPAM DETECTED' if prediction == 1 else '✅ LEGITIMATE EMAIL'}

📊 PROBABILITY ANALYSIS:
├─ Spam Probability:      {probability[1]*100:.2f}%
└─ Legitimate Probability: {probability[0]*100:.2f}%

🔍 SPAM INDICATORS DETECTED ({len([x for x in spam_indicators.values() if x])}):
"""
        for indicator, detected in spam_indicators.items():
            result += f"├─ {indicator}: {'⚠️  YES' if detected else '✓ NO'}\n"
        
        result += f"\n📈 TOP FEATURES (TF-IDF Scores):\n"
        for word, score in top_features[:5]:
            if score > 0:
                result += f"├─ '{word}': {score:.4f}\n"
        
        result += f"\n💡 RECOMMENDATION:\n"
        if prediction == 1:
            self.stats['spam_detected'] += 1
            result += "⛔ This email should be filtered as SPAM\n"
            result += "   Do not click any links or provide personal information\n"
        else:
            result += "✅ This email appears to be legitimate\n"
            result += "   Still exercise caution with unknown senders\n"
        
        result += f"\n{'='*60}\n"
        
        self.display_result(self.spam_result, result)
        
    def detect_spam_indicators(self, text):
        """Detect common spam indicators"""
        indicators = {
            "Excessive Capitals": len(re.findall(r'[A-Z]{5,}', text)) > 0,
            "Multiple Exclamations": '!!!' in text or text.count('!') > 3,
            "Money Keywords": any(word in text.lower() for word in 
                                ['money', 'cash', 'prize', 'winner', '$', 'free']),
            "Urgency Words": any(word in text.lower() for word in 
                               ['urgent', 'immediate', 'now', 'hurry', 'limited time']),
            "Suspicious Links": 'click here' in text.lower() or 'http' in text.lower(),
            "Personal Info Request": any(word in text.lower() for word in 
                                       ['password', 'credit card', 'ssn', 'verify', 'confirm']),
        }
        return indicators
        
    def browse_file(self):
        """Browse and select file for malware scanning"""
        filename = filedialog.askopenfilename(
            title="Select file to scan",
            filetypes=[("All files", "*.*"), ("Python files", "*.py"), 
                      ("Text files", "*.txt"), ("Executables", "*.exe")]
        )
        
        if filename:
            self.selected_file = filename
            self.selected_file_label.config(text=os.path.basename(filename))
            
            # Preview file content
            try:
                with open(filename, 'r', errors='ignore') as f:
                    content = f.read(2000)  # First 2000 chars
                    
                self.file_preview.config(state=tk.NORMAL)
                self.file_preview.delete(1.0, tk.END)
                self.file_preview.insert(1.0, content)
                self.file_preview.config(state=tk.DISABLED)
            except Exception as e:
                self.file_preview.config(state=tk.NORMAL)
                self.file_preview.delete(1.0, tk.END)
                self.file_preview.insert(1.0, f"Could not preview file: {str(e)}")
                self.file_preview.config(state=tk.DISABLED)
                
    def scan_malware(self):
        """Scan file for malware"""
        if not hasattr(self, 'selected_file'):
            messagebox.showwarning("Warning", "Please select a file to scan")
            return
        
        self.stats['files_scanned'] += 1
        
        # Extract features
        features = self.extract_file_features(self.selected_file)
        
        # Predict
        X = np.array([features])
        prediction = self.malware_model.predict(X)[0]
        probability = self.malware_model.predict_proba(X)[0]
        
        # Feature importance
        feature_names = ['Suspicious Strings', 'File Entropy', 'API Calls', 
                        'Size Ratio', 'Packed']
        feature_importance = self.malware_model.feature_importances_
        
        # Build result
        result = f"""
{'='*60}
🦠 MALWARE DETECTION REPORT
{'='*60}
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
File: {os.path.basename(self.selected_file)}
Size: {os.path.getsize(self.selected_file)} bytes

🎯 SCAN RESULT:
{'🚨 MALWARE DETECTED!' if prediction == 1 else '✅ FILE APPEARS CLEAN'}

📊 THREAT PROBABILITY:
├─ Malware Probability: {probability[1]*100:.2f}%
└─ Clean Probability:   {probability[0]*100:.2f}%

🔬 BEHAVIORAL ANALYSIS:
├─ Suspicious Strings:  {features[0]} detected
├─ File Entropy:        {features[1]:.2f} (normal: 4-5, packed: 7+)
├─ API Calls:           {features[2]} system calls
├─ Size Ratio:          {features[3]:.2f} (compression ratio)
└─ Packed Indicator:    {'YES ⚠️' if features[4] else 'NO ✓'}

📈 FEATURE IMPORTANCE (ML Model):
"""
        for name, importance in sorted(zip(feature_names, feature_importance), 
                                      key=lambda x: x[1], reverse=True):
            result += f"├─ {name}: {importance*100:.1f}%\n"
        
        result += f"\n🔐 FILE HASH (SHA256):\n"
        result += f"   {self.calculate_file_hash(self.selected_file)}\n"
        
        result += f"\n💡 RECOMMENDATION:\n"
        if prediction == 1:
            self.stats['malware_detected'] += 1
            result += "⛔ QUARANTINE THIS FILE IMMEDIATELY\n"
            result += "   This file exhibits malicious behavior patterns\n"
            result += "   Do NOT execute or open this file\n"
        else:
            result += "✅ File appears safe based on behavioral analysis\n"
            result += "   However, always exercise caution with unknown files\n"
        
        result += f"\n{'='*60}\n"
        
        self.display_result(self.malware_result, result)
        
    def extract_file_features(self, filename):
        """Extract features from file for malware detection"""
        try:
            with open(filename, 'rb') as f:
                content = f.read()
                
            # Feature 1: Suspicious strings
            suspicious_keywords = [b'exec', b'eval', b'system', b'shell', b'cmd',
                                 b'powershell', b'wget', b'curl', b'download']
            suspicious_count = sum(content.lower().count(keyword) 
                                 for keyword in suspicious_keywords)
            
            # Feature 2: File entropy (measure of randomness/encryption)
            entropy = self.calculate_entropy(content)
            
            # Feature 3: API calls (simulated)
            api_keywords = [b'CreateProcess', b'WriteFile', b'RegSetValue', 
                          b'VirtualAlloc', b'LoadLibrary']
            api_count = sum(content.count(keyword) for keyword in api_keywords)
            
            # Feature 4: Size ratio (actual vs expected)
            size_ratio = min(len(content) / (len(set(content)) + 1), 1.0)
            
            # Feature 5: Packed indicator
            packed = 1 if entropy > 7.0 else 0
            
            return [suspicious_count, entropy, api_count, size_ratio, packed]
            
        except Exception as e:
            return [0, 4.0, 0, 0.3, 0]  # Default safe values
            
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        entropy = 0
        for x in range(256):
            p_x = data.count(bytes([x])) / len(data)
            if p_x > 0:
                entropy += - p_x * np.log2(p_x)
        
        return entropy
        
    def calculate_file_hash(self, filename):
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(filename, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except:
            return "Unable to calculate hash"
            
    def load_sample_spam(self):
        """Load sample spam email"""
        samples = [
            """URGENT: Your account will be suspended!

Dear Valued Customer,

We have detected unusual activity on your account. You MUST verify your 
identity immediately or your account will be PERMANENTLY CLOSED!

Click here now: http://definitely-not-phishing.com

Act fast! You have only 24 hours!

This is your FINAL WARNING!!!""",
            
            """🎉 CONGRATULATIONS! YOU'VE WON! 🎉

Dear Lucky Winner,

You have been selected to receive $1,000,000 in our annual lottery!

To claim your prize, simply:
1. Click this link
2. Enter your bank details
3. Pay a small processing fee of $99

This offer expires in 1 HOUR! Don't miss out on your fortune!

CLICK HERE NOW!!!"""
        ]
        
        import random
        self.spam_input.delete(1.0, tk.END)
        self.spam_input.insert(1.0, random.choice(samples))
        
    def retrain_spam_model(self):
        """Retrain spam detection model"""
        self.log_training("\n" + "="*60)
        self.log_training("🔄 Retraining Spam Detection Model...")
        self.train_initial_models()
        messagebox.showinfo("Success", "Spam model retrained successfully!")
        
    def retrain_malware_model(self):
        """Retrain malware detection model"""
        self.log_training("\n" + "="*60)
        self.log_training("🔄 Retraining Malware Detection Model...")
        self.train_initial_models()
        messagebox.showinfo("Success", "Malware model retrained successfully!")
        
    def log_training(self, message):
        """Log message to training log"""
        self.training_log.config(state=tk.NORMAL)
        self.training_log.insert(tk.END, f"{message}\n")
        self.training_log.see(tk.END)
        self.training_log.config(state=tk.DISABLED)
        
    def display_result(self, widget, text):
        """Display result in text widget"""
        widget.config(state=tk.NORMAL)
        widget.delete(1.0, tk.END)
        widget.insert(1.0, text)
        widget.config(state=tk.DISABLED)
        
    def update_statistics_display(self):
        """Update statistics display"""
        # Clear existing widgets
        for widget in self.stats_frame.winfo_children():
            widget.destroy()
        
        # Create stats cards
        stats_data = [
            ("📧 Emails Scanned", self.stats['emails_scanned'], "#89b4fa"),
            ("🚨 Spam Detected", self.stats['spam_detected'], "#f38ba8"),
            ("📁 Files Scanned", self.stats['files_scanned'], "#a6e3a1"),
            ("🦠 Malware Detected", self.stats['malware_detected'], "#fab387"),
        ]
        
        for i, (label, value, color) in enumerate(stats_data):
            card = tk.Frame(self.stats_frame, bg="#313244", relief=tk.RAISED, bd=2)
            card.grid(row=i//2, column=i%2, padx=20, pady=20, sticky="nsew")
            
            tk.Label(card, text=label, font=("Arial", 14, "bold"),
                    bg="#313244", fg="#cdd6f4").pack(pady=(20, 10))
            
            tk.Label(card, text=str(value), font=("Arial", 36, "bold"),
                    bg="#313244", fg=color).pack(pady=(0, 20))
        
        # Configure grid
        self.stats_frame.grid_columnconfigure(0, weight=1)
        self.stats_frame.grid_columnconfigure(1, weight=1)
        self.stats_frame.grid_rowconfigure(0, weight=1)
        self.stats_frame.grid_rowconfigure(1, weight=1)
        
        # Detection rate
        if self.stats['emails_scanned'] > 0:
            spam_rate = (self.stats['spam_detected'] / self.stats['emails_scanned']) * 100
        else:
            spam_rate = 0
            
        if self.stats['files_scanned'] > 0:
            malware_rate = (self.stats['malware_detected'] / self.stats['files_scanned']) * 100
        else:
            malware_rate = 0
        
        # Info card
        info_card = tk.Frame(self.stats_frame, bg="#313244")
        info_card.grid(row=2, column=0, columnspan=2, padx=20, pady=20, sticky="ew")
        
        info_text = f"""
📊 Detection Rates:
• Spam Detection Rate: {spam_rate:.1f}%
• Malware Detection Rate: {malware_rate:.1f}%

🧠 ML Models Active:
• Naive Bayes (Spam): ✓ Trained
• Random Forest (Malware): ✓ Trained

⏱️ Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        
        tk.Label(info_card, text=info_text, font=("Consolas", 11),
                bg="#313244", fg="#a6adc8", justify=tk.LEFT).pack(pady=20)

def main():
    root = tk.Tk()
    app = SecurityAnalysisTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()