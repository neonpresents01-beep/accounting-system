import sys
import sqlite3
import hashlib
import jwt
import secrets
from datetime import datetime, date, timedelta
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
import os
import random
import json
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestRegressor, IsolationForest
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')

# ==================== سیستم امنیتی ====================
class AdvancedSecuritySystem:
    def __init__(self):
        self.users = {}
        self.sessions = {}
        self.failed_attempts = {}
        self.jwt_secret = secrets.token_urlsafe(32)
        self.init_default_users()
    
    def init_default_users(self):
        default_users = [
            {
                'username': 'admin', 'password': 'Admin123!', 'full_name': 'مدیر سیستم',
                'email': 'admin@company.com', 'role': 'super_admin', 'department': 'مدیریت',
                'permissions': ['*'], 'is_active': True
            },
            {
                'username': 'financial', 'password': 'Fin123!', 'full_name': 'مدیر مالی', 
                'email': 'financial@company.com', 'role': 'financial_manager', 'department': 'مالی',
                'permissions': ['financial.*', 'reports.*', 'dashboard.*'], 'is_active': True
            }
        ]
        
        for user_data in default_users:
            self.register_user(user_data)
    
    def hash_password(self, password):
        salt = secrets.token_hex(16)
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex() + ':' + salt
    
    def verify_password(self, password, hashed_password):
        try:
            password_hash, salt = hashed_password.split(':')
            return password_hash == hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
        except:
            return False
    
    def register_user(self, user_data):
        username = user_data['username']
        self.users[username] = {
            'username': username,
            'password': self.hash_password(user_data['password']),
            'full_name': user_data['full_name'],
            'email': user_data['email'],
            'role': user_data['role'],
            'department': user_data['department'],
            'permissions': user_data.get('permissions', []),
            'is_active': user_data.get('is_active', True),
            'created_at': datetime.now(),
            'last_login': None,
            'failed_attempts': 0
        }
    
    def login(self, username, password, ip_address="localhost"):
        if username not in self.users:
            return False, "کاربر یافت نشد"
        
        user = self.users[username]
        
        if not user['is_active']:
            return False, "حساب کاربری غیرفعال است"
        
        if user['failed_attempts'] >= 5:
            user['is_active'] = False
            return False, "حساب کاربری به دلیل ورودهای ناموفق متوالی مسدود شد"
        
        if not self.verify_password(password, user['password']):
            user['failed_attempts'] += 1
            return False, f"رمز عبور اشتباه است. {5 - user['failed_attempts']} تلاش باقی مانده"
        
        # ورود موفق
        user['last_login'] = datetime.now()
        user['failed_attempts'] = 0
        
        token_payload = {
            'username': username,
            'role': user['role'],
            'permissions': user['permissions'],
            'exp': datetime.utcnow() + timedelta(hours=8)
        }
        
        token = jwt.encode(token_payload, self.jwt_secret, algorithm='HS256')
        
        session_id = secrets.token_urlsafe(32)
        self.sessions[session_id] = {
            'username': username,
            'token': token,
            'login_time': datetime.now(),
            'last_activity': datetime.now(),
            'ip_address': ip_address
        }
        
        return True, {
            'session_id': session_id,
            'token': token,
            'user': {
                'username': user['username'],
                'full_name': user['full_name'],
                'role': user['role'],
                'permissions': user['permissions'],
                'department': user['department']
            }
        }

# ==================== پایگاه داده ====================
class AdvancedDatabaseSystem:
    def __init__(self):
        self.connection = None
        self.init_database()
    
    def init_database(self):
        try:
            self.connection = sqlite3.connect('accounting_system.db', check_same_thread=False)
            self.connection.execute("PRAGMA foreign_keys = ON")
            self.create_tables()
            self.insert_sample_data()
            print("✅ پایگاه داده راه‌اندازی شد")
        except Exception as e:
            print(f"❌ خطا در راه‌اندازی دیتابیس: {e}")
    
    def create_tables(self):
        cursor = self.connection.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                balance REAL DEFAULT 0,
                is_active BOOLEAN DEFAULT 1
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_number TEXT UNIQUE NOT NULL,
                date TEXT NOT NULL,
                type TEXT NOT NULL,
                description TEXT,
                amount REAL NOT NULL,
                account_id INTEGER,
                status TEXT DEFAULT 'completed',
                created_by TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sku TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                category TEXT,
                cost_price REAL,
                selling_price REAL,
                current_stock INTEGER DEFAULT 0,
                min_stock INTEGER DEFAULT 0,
                is_active BOOLEAN DEFAULT 1
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS customers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_code TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                type TEXT DEFAULT 'regular',
                phone TEXT,
                email TEXT,
                credit_limit REAL DEFAULT 0,
                current_balance REAL DEFAULT 0,
                is_active BOOLEAN DEFAULT 1
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS invoices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                invoice_number TEXT UNIQUE NOT NULL,
                customer_id INTEGER,
                invoice_date TEXT NOT NULL,
                total_amount REAL NOT NULL,
                tax_amount REAL DEFAULT 0,
                discount_amount REAL DEFAULT 0,
                final_amount REAL NOT NULL,
                status TEXT DEFAULT 'draft',
                payment_method TEXT,
                created_by TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS invoice_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                invoice_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                quantity INTEGER NOT NULL,
                unit_price REAL NOT NULL,
                line_total REAL NOT NULL,
                FOREIGN KEY (invoice_id) REFERENCES invoices (id) ON DELETE CASCADE,
                FOREIGN KEY (product_id) REFERENCES products (id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tax_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tax_name TEXT NOT NULL,
                tax_rate REAL NOT NULL,
                is_active BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.connection.commit()
    
    def insert_sample_data(self):
        cursor = self.connection.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM accounts")
        if cursor.fetchone()[0] == 0:
            self.insert_accounts()
            self.insert_products()
            self.insert_customers()
            self.insert_sample_transactions()
            self.insert_tax_settings()
    
    def insert_accounts(self):
        accounts = [
            ('1-101', 'صندوق', 'asset', 50000000),
            ('1-102', 'بانک ملی', 'asset', 250000000),
            ('3-101', 'درآمد فروش', 'income', 0),
            ('4-101', 'هزینه حقوق', 'expense', 0)
        ]
        
        cursor = self.connection.cursor()
        for code, name, type, balance in accounts:
            cursor.execute(
                "INSERT OR IGNORE INTO accounts (code, name, type, balance) VALUES (?, ?, ?, ?)",
                (code, name, type, balance)
            )
        self.connection.commit()
    
    def insert_products(self):
        products = [
            ('LAP-001', 'لپ‌تاپ ایسوس ROG', 'الکترونیک', 28000000, 35000000, 15, 5),
            ('MS-002', 'ماوس بی‌سیم لاجیتک', 'الکترونیک', 300000, 450000, 45, 20),
            ('KB-003', 'کیبورد مکانیکی ریزر', 'الکترونیک', 900000, 1200000, 25, 10)
        ]
        
        cursor = self.connection.cursor()
        for sku, name, category, cost, price, stock, min_stock in products:
            cursor.execute('''
                INSERT OR IGNORE INTO products 
                (sku, name, category, cost_price, selling_price, current_stock, min_stock)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (sku, name, category, cost, price, stock, min_stock))
        self.connection.commit()
    
    def insert_customers(self):
        customers = [
            ('CUST-001', 'شرکت فناوری اطلاعات', 'vip', '021-12345678', 'info@techco.com', 500000000, 125000000),
            ('CUST-002', 'آقای احمد محمدی', 'regular', '09123456789', 'ahmad@email.com', 10000000, 2500000)
        ]
        
        cursor = self.connection.cursor()
        for code, name, type, phone, email, credit_limit, balance in customers:
            cursor.execute('''
                INSERT OR IGNORE INTO customers 
                (customer_code, name, type, phone, email, credit_limit, current_balance)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (code, name, type, phone, email, credit_limit, balance))
        self.connection.commit()
    
    def insert_sample_transactions(self):
        cursor = self.connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM transactions")
        if cursor.fetchone()[0] == 0:
            transactions = [
                ('TRX-001', '2024-01-15', 'income', 'فروش لپ‌تاپ', 35000000, 1, 'admin'),
                ('TRX-002', '2024-01-16', 'expense', 'خرید ماوس', 300000, 1, 'admin'),
                ('TRX-003', '2024-01-17', 'income', 'فروش کیبورد', 1200000, 1, 'financial')
            ]
            
            for trans_num, date, type, desc, amount, acc_id, created_by in transactions:
                cursor.execute('''
                    INSERT INTO transactions 
                    (transaction_number, date, type, description, amount, account_id, created_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (trans_num, date, type, desc, amount, acc_id, created_by))
            self.connection.commit()
    
    def insert_tax_settings(self):
        cursor = self.connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM tax_settings")
        if cursor.fetchone()[0] == 0:
            taxes = [
                ('مالیات بر ارزش افزوده', 9.0),
                ('عوارض شهرداری', 1.0)
            ]
            
            for tax_name, tax_rate in taxes:
                cursor.execute('''
                    INSERT INTO tax_settings (tax_name, tax_rate) VALUES (?, ?)
                ''', (tax_name, tax_rate))
            self.connection.commit()

# ==================== سیستم چاپ ====================
class PrinterSystem:
    def __init__(self):
        self.printer_name = "پیش‌فرض"
    
    def print_receipt(self, receipt_data):
        try:
            # شبیه‌سازی چاپ فاکتور
            receipt_text = self.format_receipt(receipt_data)
            print("🧾 چاپ فاکتور:")
            print(receipt_text)
            
            # ذخیره در فایل برای چاپ واقعی
            with open('receipt.txt', 'w', encoding='utf-8') as f:
                f.write(receipt_text)
            
            return True, "فاکتور با موفقیت چاپ شد"
        except Exception as e:
            return False, f"خطا در چاپ: {str(e)}"
    
    def format_receipt(self, data):
        receipt = f"""
        🧾 فاکتور فروشگاه
        {'='*40}
        شماره فاکتور: {data['invoice_number']}
        تاریخ: {datetime.now().strftime('%Y-%m-%d %H:%M')}
        {'-'*40}
        موارد خرید:
        """
        
        for item in data.get('items', []):
            receipt += f"\n{item['name']:20} {item['quantity']} x {item['price']:,} = {item['total']:,}"
        
        receipt += f"""
        {'-'*40}
        جمع کل: {data['total_amount']:,} تومان
        تخفیف: {data['discount_amount']:,} تومان
        مالیات: {data['tax_amount']:,} تومان
        {'='*40}
        مبلغ قابل پرداخت: {data['final_amount']:,} تومان
        روش پرداخت: {data['payment_method']}
        {'='*40}
        با تشکر از خرید شما!
        """
        
        return receipt

# ==================== سیستم کارتخوان ====================
class CardReaderSystem:
    def __init__(self):
        self.is_connected = False
    
    def connect(self):
        try:
            # شبیه‌سازی اتصال به کارتخوان
            self.is_connected = True
            return True, "کارتخوان متصل شد"
        except:
            return False, "خطا در اتصال به کارتخوان"
    
    def process_payment(self, amount, card_number="", pin=""):
        if not self.is_connected:
            return False, "کارتخوان متصل نیست"
        
        try:
            # شبیه‌سازی پرداخت
            transaction_id = f"CT{random.randint(100000, 999999)}"
            
            # تأخیر شبیه‌سازی پرداخت
            QThread.msleep(2000)
            
            return True, {
                'transaction_id': transaction_id,
                'amount': amount,
                'card_number': card_number[-4:] if card_number else "****",
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        except Exception as e:
            return False, f"خطا در پرداخت: {str(e)}"

# ==================== سیستم بارکدخوان ====================
class BarcodeReaderSystem:
    def __init__(self, database):
        self.database = database
        self.is_connected = False
    
    def connect(self):
        try:
            self.is_connected = True
            return True, "بارکدخوان متصل شد"
        except:
            return False, "خطا در اتصال به بارکدخوان"
    
    def read_barcode(self, barcode_data=""):
        if not self.is_connected:
            return False, "بارکدخوان متصل نیست"
        
        try:
            # اگر داده بارکد ارائه نشده، یک محصول تصادفی انتخاب کن
            if not barcode_data:
                cursor = self.database.connection.cursor()
                cursor.execute("SELECT id, sku, name FROM products WHERE current_stock > 0 ORDER BY RANDOM() LIMIT 1")
                product = cursor.fetchone()
                if product:
                    barcode_data = product[1]  # استفاده از SKU به عنوان بارکد
                else:
                    return False, "محصولی برای تست یافت نشد"
            
            # جستجوی محصول بر اساس بارکد (SKU)
            cursor = self.database.connection.cursor()
            cursor.execute("SELECT id, sku, name, selling_price, current_stock FROM products WHERE sku = ?", (barcode_data,))
            product = cursor.fetchone()
            
            if product:
                return True, {
                    'product_id': product[0],
                    'sku': product[1],
                    'name': product[2],
                    'price': product[3],
                    'stock': product[4]
                }
            else:
                return False, "محصول با این بارکد یافت نشد"
                
        except Exception as e:
            return False, f"خطا در خواندن بارکد: {str(e)}"

# ==================== هوش مصنوعی ====================
class AdvancedAISystem:
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.init_models()
    
    def init_models(self):
        try:
            self.models['sales_forecast'] = RandomForestRegressor(n_estimators=100, random_state=42)
            self.models['fraud_detection'] = IsolationForest(contamination=0.02, random_state=42)
            self.models['customer_clustering'] = KMeans(n_clusters=4, random_state=42)
            self.scalers['financial'] = StandardScaler()
            print("✅ سیستم هوش مصنوعی راه‌اندازی شد")
        except Exception as e:
            print(f"❌ خطا در راه‌اندازی AI: {e}")
    
    def predict_sales(self, historical_data, periods=30):
        try:
            if not historical_data:
                historical_data = [random.randint(50000000, 150000000) for _ in range(90)]
            
            predictions = []
            current_date = datetime.now()
            
            for i in range(periods):
                future_date = current_date + timedelta(days=i+1)
                
                base_sales = 100000000
                seasonal_factor = self.calculate_seasonal_factor(future_date)
                monthly_trend = 1.2 if future_date.month in [3, 4, 11, 12] else 1.0
                random_factor = random.uniform(0.9, 1.1)
                
                predicted_sales = int(base_sales * seasonal_factor * monthly_trend * random_factor)
                
                predictions.append({
                    'date': future_date.strftime('%Y-%m-%d'),
                    'predicted_sales': predicted_sales,
                    'confidence': random.uniform(0.85, 0.95),
                    'trend': '📈 افزایش' if random.random() > 0.4 else '📉 کاهش'
                })
            
            return predictions
        except Exception as e:
            print(f"خطا در پیش‌بینی فروش: {e}")
            return []
    
    def calculate_seasonal_factor(self, date_obj):
        month = date_obj.month
        if month in [1, 2, 12]: return 1.3
        elif month in [3, 4, 5]: return 1.1
        elif month in [6, 7, 8]: return 0.9
        else: return 1.0

# ==================== سیستم مالیاتی ====================
class TaxSystem:
    def __init__(self, database):
        self.database = database
        self.tax_rates = {}
        self.load_tax_rates()
    
    def load_tax_rates(self):
        cursor = self.database.connection.cursor()
        cursor.execute("SELECT tax_name, tax_rate FROM tax_settings WHERE is_active = 1")
        taxes = cursor.fetchall()
        
        for tax_name, tax_rate in taxes:
            self.tax_rates[tax_name] = tax_rate
    
    def calculate_tax(self, amount, tax_name="مالیات بر ارزش افزوده"):
        if tax_name in self.tax_rates:
            return amount * (self.tax_rates[tax_name] / 100)
        return 0
    
    def calculate_total_tax(self, amount):
        total_tax = 0
        for tax_name, tax_rate in self.tax_rates.items():
            total_tax += self.calculate_tax(amount, tax_name)
        return total_tax
    
    def update_tax_rate(self, tax_name, new_rate):
        cursor = self.database.connection.cursor()
        cursor.execute('''
            UPDATE tax_settings SET tax_rate = ? WHERE tax_name = ?
        ''', (new_rate, tax_name))
        self.database.connection.commit()
        self.load_tax_rates()

# ==================== سیستم POS واقعی ====================
class CompletePOSSystem:
    def __init__(self, database, current_user):
        self.database = database
        self.current_user = current_user
        self.current_cart = []
        self.cart_total = 0
        self.tax_system = TaxSystem(database)
        self.printer_system = PrinterSystem()
        self.card_reader = CardReaderSystem()
        self.barcode_reader = BarcodeReaderSystem(database)
        self.invoice_counter = 1000
    
    def add_to_cart(self, product_id, quantity=1):
        try:
            cursor = self.database.connection.cursor()
            cursor.execute("SELECT * FROM products WHERE id = ?", (product_id,))
            product = cursor.fetchone()
            
            if not product:
                return False, "محصول یافت نشد"
            
            if product[6] < quantity:
                return False, f"موجودی کافی نیست. موجودی فعلی: {product[6]}"
            
            for item in self.current_cart:
                if item['product_id'] == product_id:
                    if item['quantity'] + quantity > product[6]:
                        return False, f"تعداد درخواستی بیشتر از موجودی است"
                    item['quantity'] += quantity
                    item['total'] = item['quantity'] * item['unit_price']
                    self.calculate_totals()
                    return True, f"تعداد {product[2]} به {item['quantity']} افزایش یافت"
            
            cart_item = {
                'product_id': product_id,
                'sku': product[1],
                'name': product[2],
                'unit_price': product[5],
                'quantity': quantity,
                'total': product[5] * quantity,
                'available_stock': product[6]
            }
            self.current_cart.append(cart_item)
            self.calculate_totals()
            return True, f"{product[2]} به سبد خرید اضافه شد"
            
        except Exception as e:
            return False, f"خطا در اضافه کردن به سبد: {str(e)}"
    
    def remove_from_cart(self, product_id):
        self.current_cart = [item for item in self.current_cart if item['product_id'] != product_id]
        self.calculate_totals()
        return True, "محصول از سبد حذف شد"
    
    def calculate_totals(self):
        self.cart_total = sum(item['total'] for item in self.current_cart)
        self.tax_amount = self.tax_system.calculate_total_tax(self.cart_total)
        self.final_amount = self.cart_total + self.tax_amount
    
    def clear_cart(self):
        self.current_cart.clear()
        self.calculate_totals()
        return True, "سبد خرید پاک شد"
    
    def process_payment(self, payment_method, discount=0):
        if not self.current_cart:
            return False, "سبد خرید خالی است"
        
        try:
            cursor = self.database.connection.cursor()
            
            invoice_number = f"INV-{datetime.now().strftime('%Y%m%d')}-{self.invoice_counter}"
            self.invoice_counter += 1
            
            discount_amount = self.cart_total * (discount / 100)
            final_after_discount = self.final_amount - discount_amount
            
            cursor.execute('''
                INSERT INTO invoices 
                (invoice_number, customer_id, invoice_date, total_amount, tax_amount, 
                 discount_amount, final_amount, status, payment_method, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                invoice_number,
                None,
                datetime.now().strftime('%Y-%m-%d'),
                self.cart_total,
                self.tax_amount,
                discount_amount,
                final_after_discount,
                'paid',
                payment_method,
                self.current_user['username']
            ))
            
            invoice_id = cursor.lastrowid
            
            for item in self.current_cart:
                cursor.execute('''
                    INSERT INTO invoice_items 
                    (invoice_id, product_id, quantity, unit_price, line_total)
                    VALUES (?, ?, ?, ?, ?)
                ''', (invoice_id, item['product_id'], item['quantity'], item['unit_price'], item['total']))
                
                cursor.execute('''
                    UPDATE products 
                    SET current_stock = current_stock - ? 
                    WHERE id = ?
                ''', (item['quantity'], item['product_id']))
            
            cursor.execute('''
                INSERT INTO transactions 
                (transaction_number, date, type, description, amount, account_id, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                f"TRX-{invoice_number}",
                datetime.now().strftime('%Y-%m-%d'),
                'income',
                f'فروش فاکتور {invoice_number}',
                final_after_discount,
                1,
                self.current_user['username']
            ))
            
            self.database.connection.commit()
            
            # چاپ فاکتور
            receipt_data = {
                'invoice_number': invoice_number,
                'items': self.current_cart,
                'total_amount': self.cart_total,
                'discount_amount': discount_amount,
                'tax_amount': self.tax_amount,
                'final_amount': final_after_discount,
                'payment_method': payment_method
            }
            self.printer_system.print_receipt(receipt_data)
            
            self.clear_cart()
            
            return True, {
                'invoice_number': invoice_number,
                'total_amount': self.cart_total,
                'tax_amount': self.tax_amount,
                'discount_amount': discount_amount,
                'final_amount': final_after_discount,
                'tax_breakdown': self.get_tax_breakdown(self.cart_total)
            }
            
        except Exception as e:
            self.database.connection.rollback()
            return False, f"خطا در پردازش پرداخت: {str(e)}"
    
    def get_tax_breakdown(self, amount):
        breakdown = {}
        for tax_name, tax_rate in self.tax_system.tax_rates.items():
            breakdown[tax_name] = {
                'rate': tax_rate,
                'amount': self.tax_system.calculate_tax(amount, tax_name)
            }
        return breakdown

# ==================== برنامه اصلی ====================
class CompleteAccountingSystem(QMainWindow):
    def __init__(self):
        super().__init__()
        self.auth_system = AdvancedSecuritySystem()
        self.database = AdvancedDatabaseSystem()
        self.ai_system = AdvancedAISystem()
        self.tax_system = TaxSystem(self.database)
        self.printer_system = PrinterSystem()
        self.card_reader = CardReaderSystem()
        self.barcode_reader = BarcodeReaderSystem(self.database)
        self.current_user = None
        self.current_token = None
        self.pos_system = None
        
        self.init_ui()
    
    def init_ui(self):
        self.setWindowTitle('سیستم کامل حسابداری هوشمند 🚀')
        self.setGeometry(100, 100, 1400, 800)
        self.show_login_page()
    
    def show_login_page(self):
        login_widget = QWidget()
        layout = QVBoxLayout()
        
        header = QLabel('🔐 ورود به سیستم حسابداری هوشمند')
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("""
            font-size: 32px; font-weight: bold; color: #2c3e50; margin: 40px; padding: 20px;
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #667eea, stop:1 #764ba2);
            border-radius: 20px; color: white;
        """)
        
        login_card = QWidget()
        login_card.setMaximumWidth(500)
        login_card.setStyleSheet("background: white; border-radius: 20px; padding: 40px;")
        
        login_layout = QVBoxLayout()
        
        form_layout = QFormLayout()
        
        self.login_username = QLineEdit()
        self.login_username.setPlaceholderText('نام کاربری')
        self.login_username.setStyleSheet("padding: 12px; font-size: 14px; border: 2px solid #bdc3c7; border-radius: 8px;")
        
        self.login_password = QLineEdit()
        self.login_password.setPlaceholderText('رمز عبور')
        self.login_password.setEchoMode(QLineEdit.Password)
        self.login_password.setStyleSheet("padding: 12px; font-size: 14px; border: 2px solid #bdc3c7; border-radius: 8px;")
        
        form_layout.addRow('👤 نام کاربری:', self.login_username)
        form_layout.addRow('🔐 رمز عبور:', self.login_password)
        
        login_btn = QPushButton('🚀 ورود به سیستم')
        login_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #00b09b, stop:1 #96c93d);
                color: white; border: none; border-radius: 10px; padding: 15px;
                font-size: 16px; font-weight: bold; margin-top: 20px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #009975, stop:1 #7ba82d);
            }
        """)
        login_btn.clicked.connect(self.handle_login)
        
        info_label = QLabel('''
        کاربران پیش‌فرض:
        👨‍💼 admin / Admin123! (مدیر سیستم)
        👩‍💼 financial / Fin123! (کاربر مالی)
        ''')
        info_label.setStyleSheet("background: #f8f9fa; padding: 15px; border-radius: 8px; margin-top: 20px; font-size: 12px;")
        
        login_layout.addLayout(form_layout)
        login_layout.addWidget(login_btn)
        login_layout.addWidget(info_label)
        login_card.setLayout(login_layout)
        
        layout.addWidget(header)
        layout.addWidget(login_card, 0, Qt.AlignCenter)
        layout.addStretch()
        
        login_widget.setLayout(layout)
        self.setCentralWidget(login_widget)
    
    def handle_login(self):
        username = self.login_username.text()
        password = self.login_password.text()
        
        if not username or not password:
            QMessageBox.warning(self, "خطا", "لطفاً نام کاربری و رمز عبور را وارد کنید")
            return
        
        success, result = self.auth_system.login(username, password)
        
        if success:
            self.current_token = result['session_id']
            self.current_user = result['user']
            self.pos_system = CompletePOSSystem(self.database, self.current_user)
            self.show_main_application()
            QMessageBox.information(self, "خوش آمدید", f"سلام {self.current_user['full_name']}! 👋")
        else:
            QMessageBox.warning(self, "خطای ورود", result)
    
    def show_main_application(self):
        self.tab_widget = QTabWidget()
        
        self.create_dashboard_tab()
        self.create_accounting_tab()
        self.create_inventory_tab()
        self.create_pos_tab()
        self.create_reports_tab()
        self.create_customers_tab()
        self.create_tax_tab()
        self.create_hardware_tab()
        self.create_settings_tab()
        
        self.setCentralWidget(self.tab_widget)
        self.apply_styles()
        self.load_all_data()
    
    def apply_styles(self):
        self.setStyleSheet("""
            QMainWindow {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #667eea, stop:1 #764ba2);
                font-family: 'Segoe UI', Tahoma;
            }
            QTabWidget::pane {
                border: 2px solid #2c3e50; border-radius: 10px; background: white;
            }
            QTabBar::tab {
                background: #34495e; color: white; padding: 12px 20px; margin: 2px;
                border-radius: 8px; font-weight: bold;
            }
            QTabBar::tab:selected {
                background: #3498db; border: 2px solid #2980b9;
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #3498db, stop:1 #2980b9);
                color: white; border: none; border-radius: 8px; padding: 10px 15px;
                font-weight: bold; margin: 3px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #2980b9, stop:1 #21618c);
            }
            QGroupBox {
                font-weight: bold; border: 2px solid #bdc3c7; border-radius: 8px; 
                margin-top: 10px; padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin; subcontrol-position: top center; 
                padding: 0 5px; background-color: #ecf0f1; color: #2c3e50;
            }
        """)
    
    def create_dashboard_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        header = QLabel('📊 داشبورد مدیریت')
        header.setStyleSheet("font-size: 28px; font-weight: bold; color: #2c3e50; margin: 20px;")
        header.setAlignment(Qt.AlignCenter)
        
        stats_layout = QHBoxLayout()
        
        cursor = self.database.connection.cursor()
        cursor.execute("SELECT SUM(amount) FROM transactions WHERE type='income'")
        total_income = cursor.fetchone()[0] or 0
        
        cursor.execute("SELECT COUNT(*) FROM products")
        total_products = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM customers")
        total_customers = cursor.fetchone()[0]
        
        cursor.execute("SELECT SUM(tax_amount) FROM invoices WHERE status='paid'")
        total_taxes = cursor.fetchone()[0] or 0
        
        stats = [
            ("💰 درآمد کل", f"{total_income:,}", "تومان", "#27ae60"),
            ("📦 محصولات", str(total_products), "قلم", "#3498db"),
            ("👥 مشتریان", str(total_customers), "نفر", "#9b59b6"),
            ("🏛️ مالیات جمع‌آوری", f"{total_taxes:,}", "تومان", "#e67e22")
        ]
        
        for title, value, unit, color in stats:
            card = QWidget()
            card.setFixedSize(200, 120)
            card.setStyleSheet(f"""
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 {color}, stop:1 #2c3e50);
                border-radius: 12px; padding: 15px;
            """)
            
            card_layout = QVBoxLayout()
            
            title_label = QLabel(title)
            title_label.setStyleSheet("color: white; font-size: 14px; font-weight: bold;")
            
            value_label = QLabel(value)
            value_label.setStyleSheet("color: white; font-size: 20px; font-weight: bold; margin: 5px 0;")
            
            unit_label = QLabel(unit)
            unit_label.setStyleSheet("color: rgba(255,255,255,0.8); font-size: 12px;")
            
            card_layout.addWidget(title_label)
            card_layout.addWidget(value_label)
            card_layout.addWidget(unit_label)
            card.setLayout(card_layout)
            stats_layout.addWidget(card)
        
        layout.addWidget(header)
        layout.addLayout(stats_layout)
        
        tab.setLayout(layout)
        self.tab_widget.addTab(tab, "🏠 داشبورد")
    
    def create_accounting_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        header = QLabel('💼 سیستم حسابداری')
        header.setStyleSheet("font-size: 24px; font-weight: bold; margin: 10px;")
        
        # نوار ابزار
        toolbar = QHBoxLayout()
        
        add_transaction_btn = QPushButton('➕ ثبت تراکنش جدید')
        refresh_btn = QPushButton('🔄 بروزرسانی')
        
        add_transaction_btn.clicked.connect(self.show_add_transaction_dialog)
        refresh_btn.clicked.connect(self.load_transactions)
        
        toolbar.addWidget(add_transaction_btn)
        toolbar.addWidget(refresh_btn)
        toolbar.addStretch()
        
        self.transactions_table = QTableWidget()
        self.transactions_table.setColumnCount(6)
        self.transactions_table.setHorizontalHeaderLabels([
            'شماره', 'تاریخ', 'نوع', 'شرح', 'مبلغ', 'وضعیت'
        ])
        
        layout.addWidget(header)
        layout.addLayout(toolbar)
        layout.addWidget(self.transactions_table)
        
        tab.setLayout(layout)
        self.tab_widget.addTab(tab, "💼 حسابداری")
    
    def create_inventory_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        header = QLabel('📦 مدیریت انبار')
        header.setStyleSheet("font-size: 24px; font-weight: bold; margin: 10px;")
        
        # نوار ابزار
        toolbar = QHBoxLayout()
        
        add_product_btn = QPushButton('➕ افزودن محصول')
        edit_product_btn = QPushButton('✏️ ویرایش محصول')
        refresh_btn = QPushButton('🔄 بروزرسانی')
        
        add_product_btn.clicked.connect(self.show_add_product_dialog)
        edit_product_btn.clicked.connect(self.show_edit_product_dialog)
        refresh_btn.clicked.connect(self.load_products)
        
        toolbar.addWidget(add_product_btn)
        toolbar.addWidget(edit_product_btn)
        toolbar.addWidget(refresh_btn)
        toolbar.addStretch()
        
        self.products_table = QTableWidget()
        self.products_table.setColumnCount(7)
        self.products_table.setHorizontalHeaderLabels([
            'SKU', 'نام', 'دسته', 'قیمت خرید', 'قیمت فروش', 'موجودی', 'حداقل'
        ])
        
        layout.addWidget(header)
        layout.addLayout(toolbar)
        layout.addWidget(self.products_table)
        
        tab.setLayout(layout)
        self.tab_widget.addTab(tab, "📦 انبار")
    
    def create_pos_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        header = QLabel('🛒 سیستم فروش (POS)')
        header.setStyleSheet("font-size: 24px; font-weight: bold; margin: 10px;")
        
        main_layout = QHBoxLayout()
        
        # سمت چپ: محصولات
        left_widget = QWidget()
        left_layout = QVBoxLayout()
        
        search_layout = QHBoxLayout()
        self.product_search = QLineEdit()
        self.product_search.setPlaceholderText('جستجوی محصول...')
        self.product_search.textChanged.connect(self.search_products)
        
        # دکمه اسکن بارکد
        barcode_btn = QPushButton('📷 اسکن بارکد')
        barcode_btn.clicked.connect(self.scan_barcode)
        
        search_layout.addWidget(self.product_search)
        search_layout.addWidget(barcode_btn)
        
        self.pos_products_table = QTableWidget()
        self.pos_products_table.setColumnCount(6)
        self.pos_products_table.setHorizontalHeaderLabels(['SKU', 'نام', 'قیمت', 'موجودی', 'دسته', 'عملیات'])
        
        left_layout.addLayout(search_layout)
        left_layout.addWidget(self.pos_products_table)
        left_widget.setLayout(left_layout)
        
        # سمت راست: سبد خرید
        right_widget = QWidget()
        right_layout = QVBoxLayout()
        
        cart_header = QLabel('🛍️ سبد خرید')
        cart_header.setStyleSheet("font-size: 18px; font-weight: bold; margin: 10px 0;")
        
        self.cart_table = QTableWidget()
        self.cart_table.setColumnCount(5)
        self.cart_table.setHorizontalHeaderLabels(['نام', 'تعداد', 'فی', 'جمع', 'حذف'])
        
        total_layout = QHBoxLayout()
        total_layout.addWidget(QLabel('💰 جمع کل:'))
        self.total_label = QLabel('0 تومان')
        self.total_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #e74c3c;")
        total_layout.addWidget(self.total_label)
        total_layout.addStretch()
        
        payment_btn = QPushButton('💳 پرداخت نهایی')
        payment_btn.clicked.connect(self.process_payment_real)
        payment_btn.setStyleSheet("background: #27ae60; font-size: 16px; padding: 12px;")
        
        clear_btn = QPushButton('🗑️ پاک کردن سبد')
        clear_btn.clicked.connect(self.clear_cart_real)
        
        right_layout.addWidget(cart_header)
        right_layout.addWidget(self.cart_table)
        right_layout.addLayout(total_layout)
        right_layout.addWidget(payment_btn)
        right_layout.addWidget(clear_btn)
        right_widget.setLayout(right_layout)
        
        main_layout.addWidget(left_widget, 2)
        main_layout.addWidget(right_widget, 1)
        
        layout.addWidget(header)
        layout.addLayout(main_layout)
        
        tab.setLayout(layout)
        self.tab_widget.addTab(tab, "🛒 فروش")
    
    def create_hardware_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        header = QLabel('🔌 مدیریت سخت‌افزار')
        header.setStyleSheet("font-size: 24px; font-weight: bold; margin: 10px;")
        
        # کارتخوان
        card_reader_group = QGroupBox("💳 کارتخوان")
        card_reader_layout = QVBoxLayout()
        
        card_status_label = QLabel(f"وضعیت: {'🟢 متصل' if self.card_reader.is_connected else '🔴 قطع'}")
        connect_card_btn = QPushButton('🔌 اتصال کارتخوان')
        test_card_btn = QPushButton('🧪 تست پرداخت')
        
        connect_card_btn.clicked.connect(self.connect_card_reader)
        test_card_btn.clicked.connect(self.test_card_payment)
        
        card_reader_layout.addWidget(card_status_label)
        card_reader_layout.addWidget(connect_card_btn)
        card_reader_layout.addWidget(test_card_btn)
        card_reader_group.setLayout(card_reader_layout)
        
        # بارکدخوان
        barcode_group = QGroupBox("📷 بارکدخوان")
        barcode_layout = QVBoxLayout()
        
        barcode_status_label = QLabel(f"وضعیت: {'🟢 متصل' if self.barcode_reader.is_connected else '🔴 قطع'}")
        connect_barcode_btn = QPushButton('🔌 اتصال بارکدخوان')
        test_barcode_btn = QPushButton('🧪 تست اسکن')
        
        connect_barcode_btn.clicked.connect(self.connect_barcode_reader)
        test_barcode_btn.clicked.connect(self.test_barcode_scan)
        
        barcode_layout.addWidget(barcode_status_label)
        barcode_layout.addWidget(connect_barcode_btn)
        barcode_layout.addWidget(test_barcode_btn)
        barcode_group.setLayout(barcode_layout)
        
        # چاپگر
        printer_group = QGroupBox("🖨️ چاپگر")
        printer_layout = QVBoxLayout()
        
        printer_status_label = QLabel("وضعیت: 🟢 آماده")
        test_printer_btn = QPushButton('🧪 تست چاپ')
        
        test_printer_btn.clicked.connect(self.test_printer)
        
        printer_layout.addWidget(printer_status_label)
        printer_layout.addWidget(test_printer_btn)
        printer_group.setLayout(printer_layout)
        
        layout.addWidget(header)
        layout.addWidget(card_reader_group)
        layout.addWidget(barcode_group)
        layout.addWidget(printer_group)
        layout.addStretch()
        
        tab.setLayout(layout)
        self.tab_widget.addTab(tab, "🔌 سخت‌افزار")

    def create_reports_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        header = QLabel('📈 گزارشات و تحلیل‌ها')
        header.setStyleSheet("font-size: 24px; font-weight: bold; margin: 10px;")
        
        # دکمه‌های گزارشات
        report_buttons_layout = QHBoxLayout()
        
        sales_report_btn = QPushButton('📊 گزارش فروش')
        financial_report_btn = QPushButton('💹 گزارش مالی')
        inventory_report_btn = QPushButton('📦 گزارش انبار')
        ai_analysis_btn = QPushButton('🤖 تحلیل هوش مصنوعی')
        
        sales_report_btn.clicked.connect(self.generate_sales_report)
        financial_report_btn.clicked.connect(self.generate_financial_report)
        inventory_report_btn.clicked.connect(self.generate_inventory_report)
        ai_analysis_btn.clicked.connect(self.show_ai_analysis)
        
        report_buttons_layout.addWidget(sales_report_btn)
        report_buttons_layout.addWidget(financial_report_btn)
        report_buttons_layout.addWidget(inventory_report_btn)
        report_buttons_layout.addWidget(ai_analysis_btn)
        
        # ناحیه نمایش گزارش
        self.report_text = QTextEdit()
        self.report_text.setReadOnly(True)
        
        layout.addWidget(header)
        layout.addLayout(report_buttons_layout)
        layout.addWidget(self.report_text)
        
        tab.setLayout(layout)
        self.tab_widget.addTab(tab, "📈 گزارشات")

    def create_customers_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        header = QLabel('👥 مدیریت مشتریان')
        header.setStyleSheet("font-size: 24px; font-weight: bold; margin: 10px;")
        
        # نوار ابزار
        toolbar = QHBoxLayout()
        
        add_customer_btn = QPushButton('➕ افزودن مشتری')
        refresh_btn = QPushButton('🔄 بروزرسانی')
        
        add_customer_btn.clicked.connect(self.show_add_customer_dialog)
        refresh_btn.clicked.connect(self.load_customers)
        
        toolbar.addWidget(add_customer_btn)
        toolbar.addWidget(refresh_btn)
        toolbar.addStretch()
        
        # جدول مشتریان
        self.customers_table = QTableWidget()
        self.customers_table.setColumnCount(8)
        self.customers_table.setHorizontalHeaderLabels([
            'کد', 'نام', 'نوع', 'تلفن', 'ایمیل', 'سقف اعتبار', 'مانده', 'وضعیت'
        ])
        
        layout.addWidget(header)
        layout.addLayout(toolbar)
        layout.addWidget(self.customers_table)
        
        tab.setLayout(layout)
        self.tab_widget.addTab(tab, "👥 مشتریان")
        
        self.load_customers()

    def create_tax_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        header = QLabel('🏛️ مدیریت مالیات')
        header.setStyleSheet("font-size: 24px; font-weight: bold; margin: 10px;")
        
        # جدول مالیات‌ها
        self.tax_table = QTableWidget()
        self.tax_table.setColumnCount(3)
        self.tax_table.setHorizontalHeaderLabels(['نام مالیات', 'نرخ (%)', 'عملیات'])
        
        # فرم افزودن/ویرایش مالیات
        form_group = QGroupBox("افزودن/ویرایش مالیات")
        form_layout = QFormLayout()
        
        self.tax_name_edit = QLineEdit()
        self.tax_rate_edit = QDoubleSpinBox()
        self.tax_rate_edit.setRange(0, 100)
        self.tax_rate_edit.setDecimals(2)
        self.tax_rate_edit.setSuffix("%")
        
        form_layout.addRow('نام مالیات:', self.tax_name_edit)
        form_layout.addRow('نرخ مالیات:', self.tax_rate_edit)
        
        button_layout = QHBoxLayout()
        add_tax_btn = QPushButton('➕ افزودن مالیات')
        update_tax_btn = QPushButton('✏️ بروزرسانی')
        
        add_tax_btn.clicked.connect(self.add_tax)
        update_tax_btn.clicked.connect(self.update_tax)
        
        button_layout.addWidget(add_tax_btn)
        button_layout.addWidget(update_tax_btn)
        
        form_layout.addRow(button_layout)
        form_group.setLayout(form_layout)
        
        layout.addWidget(header)
        layout.addWidget(self.tax_table)
        layout.addWidget(form_group)
        
        tab.setLayout(layout)
        self.tab_widget.addTab(tab, "🏛️ مالیات")
        
        self.load_tax_data()
    
    def create_settings_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        header = QLabel('⚙️ تنظیمات سیستم')
        header.setStyleSheet("font-size: 24px; font-weight: bold; margin: 10px;")
        
        # اطلاعات کاربر
        user_group = QGroupBox("👤 اطلاعات کاربر جاری")
        user_layout = QFormLayout()
        
        user_layout.addRow("نام کاربری:", QLabel(self.current_user['username']))
        user_layout.addRow("نام کامل:", QLabel(self.current_user['full_name']))
        user_layout.addRow("نقش:", QLabel(self.current_user['role']))
        user_layout.addRow("دسترسی‌ها:", QLabel(", ".join(self.current_user['permissions'])))
        
        user_group.setLayout(user_layout)
        
        # تنظیمات سیستم
        system_group = QGroupBox("🖥️ تنظیمات سیستم")
        system_layout = QFormLayout()
        
        tax_rate_spin = QDoubleSpinBox()
        tax_rate_spin.setRange(0, 20)
        tax_rate_spin.setValue(9)
        tax_rate_spin.setSuffix("%")
        
        backup_btn = QPushButton("💾 پشتیبان‌گیری از داده‌ها")
        restore_btn = QPushButton("🔄 بازیابی داده‌ها")
        
        system_layout.addRow("نرخ مالیات:", tax_rate_spin)
        system_layout.addRow(backup_btn)
        system_layout.addRow(restore_btn)
        
        system_group.setLayout(system_layout)
        
        # دکمه خروج
        logout_btn = QPushButton("🚪 خروج از سیستم")
        logout_btn.setStyleSheet("background: #e74c3c; font-size: 16px; padding: 12px;")
        logout_btn.clicked.connect(self.logout)
        
        layout.addWidget(header)
        layout.addWidget(user_group)
        layout.addWidget(system_group)
        layout.addStretch()
        layout.addWidget(logout_btn)
        
        tab.setLayout(layout)
        self.tab_widget.addTab(tab, "⚙️ تنظیمات")

    # ==================== متدهای جدید برای مدیریت داده ====================
    
    def show_add_transaction_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("➕ ثبت تراکنش جدید")
        dialog.setFixedSize(400, 500)
        layout = QVBoxLayout()
        
        form_layout = QFormLayout()
        
        trans_number_edit = QLineEdit()
        trans_number_edit.setText(f"TRX-{datetime.now().strftime('%Y%m%d')}-{random.randint(1000,9999)}")
        date_edit = QDateEdit()
        date_edit.setDate(QDate.currentDate())
        type_combo = QComboBox()
        type_combo.addItems(["income", "expense", "transfer"])
        description_edit = QLineEdit()
        amount_edit = QDoubleSpinBox()
        amount_edit.setRange(0, 1000000000)
        amount_edit.setValue(0)
        
        form_layout.addRow('شماره تراکنش:', trans_number_edit)
        form_layout.addRow('تاریخ:', date_edit)
        form_layout.addRow('نوع:', type_combo)
        form_layout.addRow('شرح:', description_edit)
        form_layout.addRow('مبلغ:', amount_edit)
        
        button_layout = QHBoxLayout()
        save_btn = QPushButton('💾 ذخیره')
        cancel_btn = QPushButton('❌ انصراف')
        
        save_btn.clicked.connect(lambda: self.save_new_transaction(
            trans_number_edit.text(),
            date_edit.date().toString('yyyy-MM-dd'),
            type_combo.currentText(),
            description_edit.text(),
            amount_edit.value(),
            dialog
        ))
        cancel_btn.clicked.connect(dialog.reject)
        
        button_layout.addWidget(save_btn)
        button_layout.addWidget(cancel_btn)
        
        layout.addLayout(form_layout)
        layout.addLayout(button_layout)
        dialog.setLayout(layout)
        dialog.exec_()
    
    def save_new_transaction(self, trans_number, date, type, description, amount, dialog):
        if not all([trans_number, description]):
            QMessageBox.warning(self, "خطا", "پر کردن فیلدهای الزامی ضروری است")
            return
        
        try:
            cursor = self.database.connection.cursor()
            cursor.execute('''
                INSERT INTO transactions 
                (transaction_number, date, type, description, amount, account_id, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (trans_number, date, type, description, amount, 1, self.current_user['username']))
            
            self.database.connection.commit()
            QMessageBox.information(self, "موفق", "تراکنش جدید با موفقیت ثبت شد")
            dialog.accept()
            self.load_transactions()
            
        except Exception as e:
            QMessageBox.critical(self, "خطا", f"خطا در ثبت تراکنش: {str(e)}")
    
    def show_add_product_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("➕ افزودن محصول جدید")
        dialog.setFixedSize(400, 500)
        layout = QVBoxLayout()
        
        form_layout = QFormLayout()
        
        sku_edit = QLineEdit()
        sku_edit.setText(f"PRD-{datetime.now().strftime('%Y%m%d')}-{random.randint(100,999)}")
        name_edit = QLineEdit()
        category_combo = QComboBox()
        category_combo.addItems(["الکترونیک", "پوشاک", "خوراکی", "اداری", "دیگر"])
        cost_edit = QDoubleSpinBox()
        cost_edit.setRange(0, 100000000)
        cost_edit.setValue(0)
        price_edit = QDoubleSpinBox()
        price_edit.setRange(0, 100000000)
        price_edit.setValue(0)
        stock_edit = QSpinBox()
        stock_edit.setRange(0, 10000)
        stock_edit.setValue(0)
        min_stock_edit = QSpinBox()
        min_stock_edit.setRange(0, 1000)
        min_stock_edit.setValue(0)
        
        form_layout.addRow('SKU:', sku_edit)
        form_layout.addRow('نام محصول:', name_edit)
        form_layout.addRow('دسته‌بندی:', category_combo)
        form_layout.addRow('قیمت خرید:', cost_edit)
        form_layout.addRow('قیمت فروش:', price_edit)
        form_layout.addRow('موجودی اولیه:', stock_edit)
        form_layout.addRow('حداقل موجودی:', min_stock_edit)
        
        button_layout = QHBoxLayout()
        save_btn = QPushButton('💾 ذخیره')
        cancel_btn = QPushButton('❌ انصراف')
        
        save_btn.clicked.connect(lambda: self.save_new_product(
            sku_edit.text(),
            name_edit.text(),
            category_combo.currentText(),
            cost_edit.value(),
            price_edit.value(),
            stock_edit.value(),
            min_stock_edit.value(),
            dialog
        ))
        cancel_btn.clicked.connect(dialog.reject)
        
        button_layout.addWidget(save_btn)
        button_layout.addWidget(cancel_btn)
        
        layout.addLayout(form_layout)
        layout.addLayout(button_layout)
        dialog.setLayout(layout)
        dialog.exec_()
    
    def save_new_product(self, sku, name, category, cost_price, selling_price, current_stock, min_stock, dialog):
        if not all([sku, name]):
            QMessageBox.warning(self, "خطا", "پر کردن فیلدهای الزامی ضروری است")
            return
        
        try:
            cursor = self.database.connection.cursor()
            cursor.execute('''
                INSERT INTO products 
                (sku, name, category, cost_price, selling_price, current_stock, min_stock)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (sku, name, category, cost_price, selling_price, current_stock, min_stock))
            
            self.database.connection.commit()
            QMessageBox.information(self, "موفق", "محصول جدید با موفقیت اضافه شد")
            dialog.accept()
            self.load_products()
            self.load_pos_products()
            
        except Exception as e:
            QMessageBox.critical(self, "خطا", f"خطا در افزودن محصول: {str(e)}")
    
    def show_edit_product_dialog(self):
        # انتخاب محصول برای ویرایش
        selected_row = self.products_table.currentRow()
        if selected_row == -1:
            QMessageBox.warning(self, "خطا", "لطفاً یک محصول را انتخاب کنید")
            return
        
        sku = self.products_table.item(selected_row, 0).text()
        
        # دریافت اطلاعات محصول از دیتابیس
        cursor = self.database.connection.cursor()
        cursor.execute("SELECT * FROM products WHERE sku = ?", (sku,))
        product = cursor.fetchone()
        
        if not product:
            QMessageBox.warning(self, "خطا", "محصول یافت نشد")
            return
        
        dialog = QDialog(self)
        dialog.setWindowTitle("✏️ ویرایش محصول")
        dialog.setFixedSize(400, 500)
        layout = QVBoxLayout()
        
        form_layout = QFormLayout()
        
        sku_edit = QLineEdit(product[1])
        sku_edit.setReadOnly(True)
        name_edit = QLineEdit(product[2])
        category_edit = QLineEdit(product[3] or "")
        cost_edit = QDoubleSpinBox()
        cost_edit.setRange(0, 100000000)
        cost_edit.setValue(product[4] or 0)
        price_edit = QDoubleSpinBox()
        price_edit.setRange(0, 100000000)
        price_edit.setValue(product[5] or 0)
        stock_edit = QSpinBox()
        stock_edit.setRange(0, 10000)
        stock_edit.setValue(product[6] or 0)
        min_stock_edit = QSpinBox()
        min_stock_edit.setRange(0, 1000)
        min_stock_edit.setValue(product[7] or 0)
        
        form_layout.addRow('SKU:', sku_edit)
        form_layout.addRow('نام محصول:', name_edit)
        form_layout.addRow('دسته‌بندی:', category_edit)
        form_layout.addRow('قیمت خرید:', cost_edit)
        form_layout.addRow('قیمت فروش:', price_edit)
        form_layout.addRow('موجودی:', stock_edit)
        form_layout.addRow('حداقل موجودی:', min_stock_edit)
        
        button_layout = QHBoxLayout()
        save_btn = QPushButton('💾 ذخیره تغییرات')
        cancel_btn = QPushButton('❌ انصراف')
        
        save_btn.clicked.connect(lambda: self.update_product(
            product[0],
            name_edit.text(),
            category_edit.text(),
            cost_edit.value(),
            price_edit.value(),
            stock_edit.value(),
            min_stock_edit.value(),
            dialog
        ))
        cancel_btn.clicked.connect(dialog.reject)
        
        button_layout.addWidget(save_btn)
        button_layout.addWidget(cancel_btn)
        
        layout.addLayout(form_layout)
        layout.addLayout(button_layout)
        dialog.setLayout(layout)
        dialog.exec_()
    
    def update_product(self, product_id, name, category, cost_price, selling_price, current_stock, min_stock, dialog):
        try:
            cursor = self.database.connection.cursor()
            cursor.execute('''
                UPDATE products 
                SET name = ?, category = ?, cost_price = ?, selling_price = ?, 
                    current_stock = ?, min_stock = ?
                WHERE id = ?
            ''', (name, category, cost_price, selling_price, current_stock, min_stock, product_id))
            
            self.database.connection.commit()
            QMessageBox.information(self, "موفق", "محصول با موفقیت بروزرسانی شد")
            dialog.accept()
            self.load_products()
            self.load_pos_products()
            
        except Exception as e:
            QMessageBox.critical(self, "خطا", f"خطا در بروزرسانی محصول: {str(e)}")

    # ==================== متدهای سخت‌افزار ====================
    
    def connect_card_reader(self):
        success, message = self.card_reader.connect()
        if success:
            QMessageBox.information(self, "اتصال", message)
            self.load_all_data()  # بروزرسانی UI
        else:
            QMessageBox.warning(self, "خطا", message)
    
    def test_card_payment(self):
        if not self.card_reader.is_connected:
            QMessageBox.warning(self, "خطا", "لطفاً ابتدا کارتخوان را متصل کنید")
            return
        
        # دیالوگ تست پرداخت
        dialog = QDialog(self)
        dialog.setWindowTitle("🧪 تست پرداخت کارتخوان")
        dialog.setFixedSize(300, 200)
        layout = QVBoxLayout()
        
        amount_label = QLabel("مبلغ تست: 10,000 تومان")
        status_label = QLabel("در حال پردازش...")
        
        layout.addWidget(amount_label)
        layout.addWidget(status_label)
        
        dialog.setLayout(layout)
        dialog.show()
        
        # پردازش پرداخت در background
        def process_payment():
            success, result = self.card_reader.process_payment(10000)
            dialog.close()
            
            if success:
                QMessageBox.information(self, "پرداخت موفق", 
                                      f"پرداخت با موفقیت انجام شد\nشماره تراکنش: {result['transaction_id']}")
            else:
                QMessageBox.warning(self, "خطا", result)
        
        QTimer.singleShot(1000, process_payment)
    
    def connect_barcode_reader(self):
        success, message = self.barcode_reader.connect()
        if success:
            QMessageBox.information(self, "اتصال", message)
        else:
            QMessageBox.warning(self, "خطا", message)
    
    def scan_barcode(self):
        if not self.barcode_reader.is_connected:
            QMessageBox.warning(self, "خطا", "لطفاً ابتدا بارکدخوان را متصل کنید")
            return
        
        # شبیه‌سازی اسکن بارکد
        success, result = self.barcode_reader.read_barcode()
        
        if success:
            # افزودن محصول به سبد خرید
            self.add_to_cart_real(result['product_id'])
            QMessageBox.information(self, "اسکن موفق", 
                                  f"محصول اسکن شد: {result['name']}\nقیمت: {result['price']:,} تومان")
        else:
            QMessageBox.warning(self, "خطا", result)
    
    def test_barcode_scan(self):
        success, result = self.barcode_reader.read_barcode()
        
        if success:
            QMessageBox.information(self, "تست موفق", 
                                  f"بارکدخوان کار می‌کند\nمحصول: {result['name']}\nقیمت: {result['price']:,} تومان")
        else:
            QMessageBox.warning(self, "خطا", result)
    
    def test_printer(self):
        test_data = {
            'invoice_number': 'TEST-001',
            'items': [{'name': 'آیتم تست', 'quantity': 1, 'price': 10000, 'total': 10000}],
            'total_amount': 10000,
            'discount_amount': 0,
            'tax_amount': 900,
            'final_amount': 10900,
            'payment_method': 'نقدی'
        }
        
        success, message = self.printer_system.print_receipt(test_data)
        if success:
            QMessageBox.information(self, "چاپ تست", "چاپگر با موفقیت تست شد\nفایل receipt.txt ایجاد شد")
        else:
            QMessageBox.warning(self, "خطا", message)

    # ==================== متدهای موجود (بقیه کد) ====================
    
    def load_all_data(self):
        self.load_transactions()
        self.load_products()
        self.load_pos_products()
        self.load_customers()
        self.load_tax_data()
    
    def load_transactions(self):
        cursor = self.database.connection.cursor()
        cursor.execute('SELECT transaction_number, date, type, description, amount, status FROM transactions ORDER BY date DESC')
        transactions = cursor.fetchall()
        
        self.transactions_table.setRowCount(len(transactions))
        for row, trans in enumerate(transactions):
            for col, value in enumerate(trans):
                self.transactions_table.setItem(row, col, QTableWidgetItem(str(value)))
        self.transactions_table.resizeColumnsToContents()
    
    def load_products(self):
        cursor = self.database.connection.cursor()
        cursor.execute("SELECT sku, name, category, cost_price, selling_price, current_stock, min_stock FROM products")
        products = cursor.fetchall()
        
        self.products_table.setRowCount(len(products))
        for row, product in enumerate(products):
            for col, value in enumerate(product):
                self.products_table.setItem(row, col, QTableWidgetItem(str(value)))
        self.products_table.resizeColumnsToContents()
    
    def load_pos_products(self):
        cursor = self.database.connection.cursor()
        cursor.execute("SELECT id, sku, name, selling_price, current_stock, category FROM products WHERE current_stock > 0")
        products = cursor.fetchall()
        
        self.pos_products_table.setRowCount(len(products))
        
        for row, product in enumerate(products):
            self.pos_products_table.setItem(row, 0, QTableWidgetItem(str(product[1])))
            self.pos_products_table.setItem(row, 1, QTableWidgetItem(str(product[2])))
            self.pos_products_table.setItem(row, 2, QTableWidgetItem(f"{product[3]:,}"))
            self.pos_products_table.setItem(row, 3, QTableWidgetItem(str(product[4])))
            self.pos_products_table.setItem(row, 4, QTableWidgetItem(str(product[5])))
            
            add_btn = QPushButton('➕ اضافه')
            add_btn.clicked.connect(lambda checked, p_id=product[0]: self.add_to_cart_real(p_id))
            self.pos_products_table.setCellWidget(row, 5, add_btn)
        
        self.pos_products_table.resizeColumnsToContents()
    
    def load_customers(self):
        cursor = self.database.connection.cursor()
        cursor.execute('''
            SELECT customer_code, name, type, phone, email, credit_limit, current_balance, is_active
            FROM customers
        ''')
        customers = cursor.fetchall()
        
        self.customers_table.setRowCount(len(customers))
        for row, customer in enumerate(customers):
            for col, value in enumerate(customer):
                item = QTableWidgetItem(str(value))
                
                # رنگ‌آمیزی وضعیت
                if col == 7:  # ستون وضعیت
                    item.setBackground(QColor('#27ae60') if value else QColor('#e74c3c'))
                    item.setText("فعال" if value else "غیرفعال")
                
                self.customers_table.setItem(row, col, item)
        
        self.customers_table.resizeColumnsToContents()
    
    def load_tax_data(self):
        cursor = self.database.connection.cursor()
        cursor.execute("SELECT tax_name, tax_rate, id FROM tax_settings WHERE is_active = 1")
        taxes = cursor.fetchall()
        
        self.tax_table.setRowCount(len(taxes))
        for row, (tax_name, tax_rate, tax_id) in enumerate(taxes):
            self.tax_table.setItem(row, 0, QTableWidgetItem(tax_name))
            self.tax_table.setItem(row, 1, QTableWidgetItem(f"{tax_rate}%"))
            
            delete_btn = QPushButton('🗑️ حذف')
            delete_btn.clicked.connect(lambda checked, tid=tax_id: self.delete_tax(tid))
            self.tax_table.setCellWidget(row, 2, delete_btn)
        
        self.tax_table.resizeColumnsToContents()
    
    def search_products(self):
        search_text = self.product_search.text().lower()
        for row in range(self.pos_products_table.rowCount()):
            product_name = self.pos_products_table.item(row, 1).text().lower()
            if search_text in product_name:
                self.pos_products_table.setRowHidden(row, False)
            else:
                self.pos_products_table.setRowHidden(row, True)
    
    def add_to_cart_real(self, product_id):
        success, message = self.pos_system.add_to_cart(product_id)
        if success:
            self.update_cart_display()
            QMessageBox.information(self, "سبد خرید", message)
        else:
            QMessageBox.warning(self, "خطا", message)
    
    def update_cart_display(self):
        self.cart_table.setRowCount(len(self.pos_system.current_cart))
        
        for row, item in enumerate(self.pos_system.current_cart):
            self.cart_table.setItem(row, 0, QTableWidgetItem(item['name']))
            self.cart_table.setItem(row, 1, QTableWidgetItem(str(item['quantity'])))
            self.cart_table.setItem(row, 2, QTableWidgetItem(f"{item['unit_price']:,}"))
            self.cart_table.setItem(row, 3, QTableWidgetItem(f"{item['total']:,}"))
            
            delete_btn = QPushButton('🗑️ حذف')
            delete_btn.clicked.connect(lambda checked, p_id=item['product_id']: self.remove_from_cart_real(p_id))
            self.cart_table.setCellWidget(row, 4, delete_btn)
        
        self.total_label.setText(f"{self.pos_system.cart_total:,} تومان")
        self.cart_table.resizeColumnsToContents()
    
    def remove_from_cart_real(self, product_id):
        success, message = self.pos_system.remove_from_cart(product_id)
        if success:
            self.update_cart_display()
            QMessageBox.information(self, "سبد خرید", message)
    
    def clear_cart_real(self):
        success, message = self.pos_system.clear_cart()
        if success:
            self.update_cart_display()
            QMessageBox.information(self, "سبد خرید", message)
    
    def process_payment_real(self):
        if not self.pos_system.current_cart:
            QMessageBox.warning(self, "خطا", "سبد خرید خالی است!")
            return
        
        # دیالوگ پرداخت
        dialog = QDialog(self)
        dialog.setWindowTitle("💳 پرداخت نهایی")
        dialog.setFixedSize(400, 350)
        layout = QVBoxLayout()
        
        # اطلاعات سبد خرید
        cart_info = QLabel(f"جمع کل: {self.pos_system.cart_total:,} تومان\nمالیات: {self.pos_system.tax_amount:,} تومان\nمبلغ نهایی: {self.pos_system.final_amount:,} تومان")
        cart_info.setStyleSheet("font-size: 14px; padding: 10px; background: #f8f9fa; border-radius: 8px;")
        
        # روش پرداخت
        payment_layout = QHBoxLayout()
        payment_layout.addWidget(QLabel("روش پرداخت:"))
        payment_combo = QComboBox()
        payment_combo.addItems(["نقدی", "کارت بانکی", "آنلاین", "اعتباری"])
        payment_layout.addWidget(payment_combo)
        
        # تخفیف
        discount_layout = QHBoxLayout()
        discount_layout.addWidget(QLabel("تخفیف (%):"))
        discount_spin = QSpinBox()
        discount_spin.setRange(0, 50)
        discount_spin.setValue(0)
        discount_layout.addWidget(discount_spin)
        
        # چاپ فاکتور
        print_layout = QHBoxLayout()
        print_checkbox = QCheckBox("چاپ فاکتور")
        print_checkbox.setChecked(True)
        print_layout.addWidget(print_checkbox)
        
        # دکمه‌ها
        button_layout = QHBoxLayout()
        confirm_btn = QPushButton("✅ تایید پرداخت")
        cancel_btn = QPushButton("❌ انصراف")
        
        confirm_btn.clicked.connect(lambda: self.finalize_payment(
            payment_combo.currentText(), 
            discount_spin.value(), 
            print_checkbox.isChecked(),
            dialog
        ))
        cancel_btn.clicked.connect(dialog.reject)
        
        button_layout.addWidget(confirm_btn)
        button_layout.addWidget(cancel_btn)
        
        layout.addWidget(QLabel("🎯 اطلاعات پرداخت"))
        layout.addWidget(cart_info)
        layout.addLayout(payment_layout)
        layout.addLayout(discount_layout)
        layout.addLayout(print_layout)
        layout.addLayout(button_layout)
        
        dialog.setLayout(layout)
        dialog.exec_()
    
    def finalize_payment(self, payment_method, discount, should_print, dialog):
        success, result = self.pos_system.process_payment(payment_method, discount)
        
        if success:
            dialog.accept()
            invoice_info = result
            
            # نمایش فاکتور با جزئیات مالیات
            receipt_text = f"""
            🧾 فاکتور فروش
            ───────────────────
            شماره فاکتور: {invoice_info['invoice_number']}
            تاریخ: {datetime.now().strftime('%Y-%m-%d %H:%M')}
            ───────────────────
            جمع کل: {invoice_info['total_amount']:,} تومان
            تخفیف: {invoice_info['discount_amount']:,} تومان
            ───────────────────
            📋 جزئیات مالیات:
            """
            
            for tax_name, tax_info in invoice_info['tax_breakdown'].items():
                receipt_text += f"\n   • {tax_name} ({tax_info['rate']}%): {tax_info['amount']:,.0f} تومان"
            
            receipt_text += f"\n   • مجموع مالیات: {invoice_info['tax_amount']:,.0f} تومان"
            receipt_text += f"\n───────────────────"
            receipt_text += f"\n💰 مبلغ قابل پرداخت: {invoice_info['final_amount']:,} تومان"
            receipt_text += f"\n💳 روش پرداخت: {payment_method}"
            receipt_text += f"\n\n✅ پرداخت با موفقیت انجام شد"
            
            if should_print:
                receipt_text += f"\n🖨️ فاکتور چاپ شد"
            
            QMessageBox.information(self, "پرداخت موفق", receipt_text)
            self.update_cart_display()
            self.load_all_data()
        else:
            QMessageBox.critical(self, "خطای پرداخت", result)

    def generate_sales_report(self):
        cursor = self.database.connection.cursor()
        
        # آمار فروش
        cursor.execute('''
            SELECT 
                COUNT(*) as total_invoices,
                SUM(final_amount) as total_sales,
                AVG(final_amount) as avg_sale,
                MAX(final_amount) as max_sale
            FROM invoices 
            WHERE status = 'paid'
        ''')
        stats = cursor.fetchone()
        
        # محصولات پرفروش
        cursor.execute('''
            SELECT p.name, SUM(ii.quantity) as total_sold
            FROM invoice_items ii
            JOIN products p ON ii.product_id = p.id
            GROUP BY p.name
            ORDER BY total_sold DESC
            LIMIT 5
        ''')
        top_products = cursor.fetchall()
        
        report = f"""
        📊 گزارش جامع فروش
        ─────────────────────────────
        📈 آمار کلی:
        • تعداد فاکتورها: {stats[0]:,}
        • مجموع فروش: {stats[1]:,} تومان
        • میانگین هر فاکتور: {stats[2]:,.0f} تومان
        • بیشترین فروش: {stats[3]:,} تومان
        
        🏆 محصولات پرفروش:
        """
        
        for i, (product, quantity) in enumerate(top_products, 1):
            report += f"\n{i}. {product}: {quantity:,} عدد"
        
        self.report_text.setText(report)

    def generate_financial_report(self):
        cursor = self.database.connection.cursor()
        
        # تراکنش‌های مالی
        cursor.execute('''
            SELECT type, COUNT(*), SUM(amount)
            FROM transactions 
            GROUP BY type
        ''')
        transactions = cursor.fetchall()
        
        # موجودی حساب‌ها
        cursor.execute('''
            SELECT name, balance 
            FROM accounts 
            WHERE is_active = 1
        ''')
        accounts = cursor.fetchall()
        
        report = """
        💹 گزارش وضعیت مالی
        ─────────────────────────────
        💰 تراکنش‌ها بر اساس نوع:
        """
        
        for trans_type, count, amount in transactions:
            report += f"\n• {trans_type}: {count:,} تراکنش - {amount:,} تومان"
        
        report += "\n\n🏦 موجودی حساب‌ها:"
        total_balance = 0
        for name, balance in accounts:
            report += f"\n• {name}: {balance:,} تومان"
            total_balance += balance
        
        report += f"\n\n💰 مجموع موجودی: {total_balance:,} تومان"
        
        self.report_text.setText(report)

    def generate_inventory_report(self):
        cursor = self.database.connection.cursor()
        
        # محصولات کم‌موجود
        cursor.execute('''
            SELECT name, current_stock, min_stock
            FROM products 
            WHERE current_stock <= min_stock AND is_active = 1
        ''')
        low_stock = cursor.fetchall()
        
        # ارزش موجودی
        cursor.execute('''
            SELECT SUM(current_stock * cost_price)
            FROM products
        ''')
        total_value = cursor.fetchone()[0] or 0
        
        report = f"""
        📦 گزارش وضعیت انبار
        ─────────────────────────────
        💰 ارزش کل موجودی: {total_value:,} تومان
        
        ⚠️  محصولات نیازمند سفارش:
        """
        
        if low_stock:
            for name, current, minimum in low_stock:
                report += f"\n• {name}: موجودی {current} (حداقل: {minimum})"
        else:
            report += "\n✅ همه محصولات موجودی کافی دارند"
        
        self.report_text.setText(report)

    def show_ai_analysis(self):
        # پیش‌بینی فروش با هوش مصنوعی
        predictions = self.ai_system.predict_sales(None, 7)
        
        report = """
        🤖 تحلیل هوش مصنوعی
        ─────────────────────────────
        📊 پیش‌بینی فروش 7 روز آینده:
        """
        
        for pred in predictions:
            report += f"\n📅 {pred['date']}:"
            report += f"\n   • پیش‌بینی: {pred['predicted_sales']:,} تومان"
            report += f"\n   • اطمینان: {pred['confidence']:.1%}"
            report += f"\n   • روند: {pred['trend']}\n"
        
        report += "\n🎯 توصیه‌ها:\n"
        report += "• موجودی محصولات پرفروش را افزایش دهید\n"
        report += "• برای روزهای پرترافیک برنامه‌ریزی کنید\n"
        report += "• پیشنهادات ویژه برای محصولات کم‌فروش\n"
        
        self.report_text.setText(report)

    def show_add_customer_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("➕ افزودن مشتری جدید")
        dialog.setFixedSize(400, 500)
        layout = QVBoxLayout()
        
        # فیلدهای فرم
        form_layout = QFormLayout()
        
        code_edit = QLineEdit()
        code_edit.setText(f"CUST-{datetime.now().strftime('%Y%m%d')}-{random.randint(100,999)}")
        name_edit = QLineEdit()
        type_combo = QComboBox()
        type_combo.addItems(["regular", "vip", "gold"])
        phone_edit = QLineEdit()
        email_edit = QLineEdit()
        credit_edit = QDoubleSpinBox()
        credit_edit.setRange(0, 1000000000)
        credit_edit.setValue(10000000)
        
        form_layout.addRow('کد مشتری:', code_edit)
        form_layout.addRow('نام کامل:', name_edit)
        form_layout.addRow('نوع مشتری:', type_combo)
        form_layout.addRow('تلفن:', phone_edit)
        form_layout.addRow('ایمیل:', email_edit)
        form_layout.addRow('سقف اعتبار:', credit_edit)
        
        # دکمه‌ها
        button_layout = QHBoxLayout()
        save_btn = QPushButton('💾 ذخیره')
        cancel_btn = QPushButton('❌ انصراف')
        
        save_btn.clicked.connect(lambda: self.save_new_customer(
            code_edit.text(), name_edit.text(), type_combo.currentText(),
            phone_edit.text(), email_edit.text(), credit_edit.value(), dialog
        ))
        cancel_btn.clicked.connect(dialog.reject)
        
        button_layout.addWidget(save_btn)
        button_layout.addWidget(cancel_btn)
        
        layout.addLayout(form_layout)
        layout.addLayout(button_layout)
        dialog.setLayout(layout)
        dialog.exec_()

    def save_new_customer(self, code, name, type, phone, email, credit_limit, dialog):
        if not all([code, name]):
            QMessageBox.warning(self, "خطا", "پر کردن فیلدهای الزامی ضروری است")
            return
        
        try:
            cursor = self.database.connection.cursor()
            cursor.execute('''
                INSERT INTO customers 
                (customer_code, name, type, phone, email, credit_limit, current_balance)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (code, name, type, phone, email, credit_limit, 0))
            
            self.database.connection.commit()
            QMessageBox.information(self, "موفق", "مشتری جدید با موفقیت اضافه شد")
            dialog.accept()
            self.load_customers()
            
        except Exception as e:
            QMessageBox.critical(self, "خطا", f"خطا در ذخیره مشتری: {str(e)}")

    def add_tax(self):
        tax_name = self.tax_name_edit.text()
        tax_rate = self.tax_rate_edit.value()
        
        if not tax_name:
            QMessageBox.warning(self, "خطا", "لطفاً نام مالیات را وارد کنید")
            return
        
        try:
            cursor = self.database.connection.cursor()
            cursor.execute('''
                INSERT INTO tax_settings (tax_name, tax_rate) VALUES (?, ?)
            ''', (tax_name, tax_rate))
            
            self.database.connection.commit()
            QMessageBox.information(self, "موفق", "مالیات جدید با موفقیت اضافه شد")
            self.tax_name_edit.clear()
            self.tax_rate_edit.setValue(0)
            self.load_tax_data()
            self.tax_system.load_tax_rates()
            
        except Exception as e:
            QMessageBox.critical(self, "خطا", f"خطا در افزودن مالیات: {str(e)}")
    
    def update_tax(self):
        # برای سادگی، اولین مالیات را بروزرسانی می‌کند
        tax_name = self.tax_name_edit.text()
        tax_rate = self.tax_rate_edit.value()
        
        if not tax_name:
            QMessageBox.warning(self, "خطا", "لطفاً نام مالیات را وارد کنید")
            return
        
        try:
            self.tax_system.update_tax_rate(tax_name, tax_rate)
            QMessageBox.information(self, "موفق", "نرخ مالیات با موفقیت بروزرسانی شد")
            self.load_tax_data()
            
        except Exception as e:
            QMessageBox.critical(self, "خطا", f"خطا در بروزرسانی مالیات: {str(e)}")
    
    def delete_tax(self, tax_id):
        reply = QMessageBox.question(self, "حذف مالیات", 
                                   "آیا از حذف این مالیات اطمینان دارید؟",
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            try:
                cursor = self.database.connection.cursor()
                cursor.execute("UPDATE tax_settings SET is_active = 0 WHERE id = ?", (tax_id,))
                self.database.connection.commit()
                QMessageBox.information(self, "موفق", "مالیات با موفقیت حذف شد")
                self.load_tax_data()
                self.tax_system.load_tax_rates()
                
            except Exception as e:
                QMessageBox.critical(self, "خطا", f"خطا در حذف مالیات: {str(e)}")

    def logout(self):
        reply = QMessageBox.question(self, "خروج", "آیا از خروج از سیستم اطمینان دارید؟",
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.current_user = None
            self.current_token = None
            self.show_login_page()

# ==================== راه‌اندازی برنامه ====================
if __name__ == '__main__':
    app = QApplication(sys.argv)
    
    # تنظیم فونت فارسی (اصلاح شده)
    font = QFont()
    font.setFamily("B Nazanin")
    font.setPointSize(10)
    app.setFont(font)
    
    # ایجاد و نمایش برنامه
    window = CompleteAccountingSystem()
    window.show()
    
    sys.exit(app.exec_())