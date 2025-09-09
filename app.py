from itertools import product
from flask import Flask, jsonify, render_template, request, redirect, send_file, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import smtplib, email
from email.message import EmailMessage
import sqlite3
from flask import jsonify
import csv
import io
from reportlab.platypus import Image
from io import BytesIO
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER , TA_LEFT
from reportlab.lib import colors

app = Flask(__name__)
app.secret_key = 's3cr3t_k3y_sh31fsm@rt' # Secret key for session management

def get_db_connection():
    conn = sqlite3.connect('shelfsmart.db')
    conn.row_factory = sqlite3.Row
    return conn

def get_user(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, password, role FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    return user

def login_required(*role):  # accepts any number of roles
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user_id" not in session:
                flash("Please log in to access this page.", "error")
                return redirect(url_for("login"))

            # Role check
            if role:
                user_role = session.get("role")
                if user_role not in role:
                    flash("You do not have permission to access this page.", "error")
                    return redirect(url_for("dashboard"))

            return f(*args, **kwargs)
        return decorated_function
    return decorator

# 🔑 Session settings
app.config["SESSION_PERMANENT"] = False   # expires when browser closes
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)  # optional timeout


def create_tables():
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'manager', 'staff')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # 2. Products table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_name TEXT NOT NULL,
            category_id INTEGER NOT NULL,
            subcategory_id INTEGER NOT NULL,
            category_group_id INTEGER,
            sku TEXT NOT NULL UNIQUE,
            supplier_id INTEGER,
            unit_id INTEGER NOT NULL,
            quantity_in_stock INTEGER DEFAULT 0 NOT NULL,
            reorder_level INTEGER DEFAULT 0 NOT NULL,
            purchase_price REAL NOT NULL,
            selling_price REAL NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (category_id) REFERENCES categories(id),
            FOREIGN KEY (unit_id) REFERENCES units(id),
            FOREIGN KEY (subcategory_id) REFERENCES subcategories(id),
            FOREIGN KEY (category_group_id) REFERENCES categoriesgroups(id)
        )
    ''')

    # 3. Categories table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category_name TEXT NOT NULL,
            description TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # 4. Sub Categories table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS subcategories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category_id INTEGER NOT NULL,             -- Parent category
            subcategory_name TEXT NOT NULL,           -- Name of the subcategory
            description TEXT,                         -- Optional details
            status TEXT DEFAULT 'active' CHECK(status IN ('active','inactive')),  
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS categoriesgroups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subcategory_id INTEGER NOT NULL,
            group_name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (subcategory_id) REFERENCES subcategories(id) ON DELETE CASCADE
        )
    ''')

    # 5. Unit Measurements table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS units (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            unit_name TEXT NOT NULL UNIQUE,
            abbreviation TEXT NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # 6. Suppliers table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS suppliers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            supplier_name TEXT NOT NULL,
            contact_person TEXT NOT NULL,
            phone INTEGER NOT NULL,
            email TEXT NOT NULL UNIQUE,
            address TEXT NOT NULL,
            status TEXT DEFAULT 'active' CHECK(status IN ('active', 'inactive')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # 7. Purchase table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS purchases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            supplier_id INTEGER NOT NULL,
            purchase_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            total_amount REAL NOT NULL,
            status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'completed', 'cancelled')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (supplier_id) REFERENCES suppliers(id)
        )
    ''')

    # 8. Purchase Items table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS purchase_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            purchase_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity REAL NOT NULL,
            unit_price REAL NOT NULL,
            total_price REAL GENERATED ALWAYS AS (quantity * unit_price) VIRTUAL,
            FOREIGN KEY (purchase_id) REFERENCES purchases(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        )
   ''')

    # 9. Sales table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sales (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            invoice_number TEXT NOT NULL UNIQUE,
            customer_id TEXT NOT NULL,
            total_amount REAL NOT NULL,
            payment_method TEXT,
            sale_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (customer_id) REFERENCES customers(id)
        )
    ''')

    # 10. Sales Items table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sales_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sale_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            unit_price REAL NOT NULL,
            total_price REAL NOT NULL,
            FOREIGN KEY (sale_id) REFERENCES sales(id) ON DELETE CASCADE,
            FOREIGN KEY (product_id) REFERENCES products(id)
        )
    ''')

    # 11. Invoices table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS invoices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            invoice_number TEXT NOT NULL UNIQUE,
            customer_name TEXT NOT NULL,
            total_amount REAL NOT NULL,
            invoice_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
            created_by INTEGER NOT NULL,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    ''')

    # 12. Invoice Items table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS invoice_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            invoice_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            unit_price REAL NOT NULL,
            total_price REAL NOT NULL,
            FOREIGN KEY (invoice_id) REFERENCES invoices(id) ON DELETE CASCADE,
            FOREIGN KEY (product_id) REFERENCES products(id)
        )
    ''')

    # 13. Customers table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_name TEXT NOT NULL,
            contact_number TEXT NOT NULL,
            email TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
        )
    ''')

    # 14. Users Activity Log table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            page_name TEXT NOT NULL,
            time_spent_seconds INTEGER DEFAULT 0,
            activity_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    # 15. User Session table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            logout_time TIMESTAMP,                              -- NULL while user is logged in
            session_duration_seconds INTEGER DEFAULT 0,         -- in seconds, calculated on logout
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    # 16. Stock Log table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS stock_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            change_type TEXT NOT NULL CHECK(change_type IN ('purchase','sale','adjustment')),
            reference_id INTEGER,
            quantity_change INTEGER NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (product_id) REFERENCES products(id)
        )
    ''')


    # 17. General Logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,                   -- who performed the action
            action_type TEXT NOT NULL,                  -- e.g., 'login', 'add_product', 'edit_sale', 'delete_customer', 'purchase', etc.
            reference_table TEXT,                       -- which table was affected: 'products', 'sales', 'customers', etc.
            reference_id INTEGER,                       -- id of the record in the reference_table
            description TEXT,                           -- optional text describing the action
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    conn.commit()
    conn.close()

#Call function to create tables at startup
create_tables()


def generate_invoice_number():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM sales")
    count = cursor.fetchone()[0] + 1
    conn.close()
    return f"INV-{datetime.now().year}-{count:04d}"  # e.g., INV-2025-0001

# Helper function for sales trends
def get_sales_trends(conn, range_type='daily'):
    today = datetime.today()
    labels = []
    sales_data = []

    if range_type == 'daily':
        days = [(today - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(29, -1, -1)]
        for day in days:
            result = conn.execute('''
                SELECT SUM(total_amount) as total
                FROM sales
                WHERE DATE(sale_date) = ?
            ''', (day,)).fetchone()
            sales_data.append(result['total'] or 0)
            labels.append(day)

    elif range_type == 'weekly':
        for i in range(11, -1, -1):
            week_start = (today - timedelta(weeks=i)).strftime('%Y-%m-%d')
            week_end = (today - timedelta(weeks=i-1, days=1)).strftime('%Y-%m-%d')
            result = conn.execute('''
                SELECT SUM(total_amount) as total
                FROM sales
                WHERE DATE(sale_date) BETWEEN ? AND ?
            ''', (week_start, week_end)).fetchone()
            sales_data.append(result['total'] or 0)
            labels.append(f"Week {12-i}")

    elif range_type == 'monthly':
        for i in range(11, -1, -1):
            month_start = (today.replace(day=1) - timedelta(days=i*30)).strftime('%Y-%m-01')
            month_end = (today.replace(day=1) - timedelta(days=i*30)).replace(day=28).strftime('%Y-%m-%d')
            result = conn.execute('''
                SELECT SUM(total_amount) as total
                FROM sales
                WHERE DATE(sale_date) BETWEEN ? AND ?
            ''', (month_start, month_end)).fetchone()
            sales_data.append(result['total'] or 0)
            labels.append(month_start[:7])

    return labels, sales_data


# Route for Home
@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('login'))

@app.before_request
def make_session_permanent():
    session.permanent = False # Session lasts until browser is closed

# Route for Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        conn = sqlite3.connect('shelfsmart.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        user = cursor.execute(
            "SELECT * FROM users WHERE username = ? AND role = ?",
            (username, role)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session.permanent = False 
            flash('Login successful!', 'success')

            if user['role'] == 'admin':
                return redirect('/dashboard')
            elif user['role'] == 'manager':
                return redirect('/dashboard')
            elif user['role'] == 'staff':
                return redirect('/dashboard')
        else:
            flash('Invalid credentials.', 'danger')
    
    return render_template('login.html')

# Route for Signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    conn = sqlite3.connect("shelfsmart.db")
    cursor = conn.cursor()

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            # Add your code logic here
            cursor.execute('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
                           (username, email, hashed_password, role))
            conn.commit()
            flash('Signup successful! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists.', 'error')
        except Exception as e:
            flash(f"An error occurred: {str(e)}", "error")
        finally:
            conn.close()
    return render_template('signup.html')

# Route for Logout
@app.route('/logout')
@login_required()  # 👈 FIXED
def logout():
    session.clear()
    flash('Logged out', 'info')
    return redirect(url_for('login'))

# Dashboard route
@app.route('/dashboard')
@login_required()
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('shelfsmart.db')  # Replace with your DB path
    cursor = conn.cursor()

    username = session.get('username')
    role = session.get('role')

    # Greeting
    hour = datetime.now().hour
    if hour < 5:
        greeting = "⛅️Good Morning 💐"
    elif hour < 12:
        greeting = "🌞Good Morning 💐"
    elif hour < 14:
        greeting = "🌤️Good Afternoon 💐"
    elif hour < 20:
        greeting = "💐 Good Evening 💐"
    else:
        greeting = "💐 Good Evening 💐"

    # --- Categories Chart Data ---
    cursor.execute("SELECT category_name, COUNT(*) FROM categories GROUP BY category_name")
    categories = cursor.fetchall()
    category_labels = [c[0] for c in categories] if categories else []
    category_values = [c[1] for c in categories] if categories else []

    # --- Example: Sales Data Chart ---
    cursor.execute("SELECT sale_date, SUM(total_amount) FROM sales GROUP BY sale_date")
    sales = cursor.fetchall()

    sales_dates = [s[0] for s in sales] if sales else []
    sales_totals = [s[1] for s in sales] if sales else []

    # --- Example: Low Stock Alert Count ---
    cursor.execute("SELECT COUNT(*) FROM products WHERE quantity_in_stock <= reorder_level")
    row = cursor.fetchone()
    low_stock_count = row[0] if row else 0

    conn.close()

    conn = get_db_connection()
    try:
        # --- Stats ---
        total_products = conn.execute("SELECT COUNT(*) FROM products").fetchone()[0] or 0
        
        today_sales = conn.execute("SELECT COUNT(*) FROM sales WHERE DATE(sale_date)=DATE('now','localtime')").fetchone()[0] or 0
        
        total_sales = conn.execute("SELECT COUNT(*) FROM sales").fetchone()[0] or 0
        
        today_value = conn.execute("SELECT SUM(total_amount) FROM sales WHERE DATE(sale_date)=DATE('now','localtime')").fetchone()[0] or 0
        
        low_stock_count = conn.execute("SELECT COUNT(*) FROM products WHERE quantity_in_stock <= reorder_level").fetchone()[0] or 0

    except Exception as e:
        flash(f"Error loading dashboard data: {e}", "danger")
        total_products = today_sales = total_sales = today_value = low_stock_count = 0
        sales_labels = sales_values = []
    finally:
        conn.close()

    return render_template(
        'dashboard.html',
        username=username,
        role=role,
        greeting=greeting,
        total_products=total_products,
        today_sales=today_sales,
        total_sales=total_sales,
        today_value=today_value,
        low_stock_count=low_stock_count,
        category_labels=category_labels,
        category_values=category_values,
        sales_dates=sales_dates,
        sales_totals=sales_totals
    )


# AJAX endpoint to fetch sales trends dynamically
@app.route('/sales_trends')
@login_required()
def sales_trends():
    range_type = request.args.get('range', 'daily')
    conn = get_db_connection()
    try:
        labels, values = get_sales_trends(conn, range_type)
    finally:
        conn.close()
    return jsonify({'labels': labels, 'values': values})

# Route for Add Products
@app.route('/add_product', methods=['GET', 'POST'])
@login_required("admin")
def add_product():

    conn = get_db_connection()

    if request.method == "POST":
        product_name = request.form["product_name"]
        category_id = request.form["category_id"]
        subcategory_id = request.form["subcategory_id"]
        category_group_id = request.form["category_group_id"]
        sku = request.form["sku"]
        supplier_id = request.form["supplier_id"]
        unit_id = request.form["unit_id"]
        quantity_in_stock = request.form["quantity_in_stock"]
        reorder_level = request.form["reorder_level"]
        purchase_price = request.form["purchase_price"]
        selling_price = request.form["selling_price"]

        if not product_name or not sku:
            flash("Product Name and SKU are required!", "danger")
            return redirect(url_for("add_product"))

        try:
            conn = get_db_connection()
            conn.execute(
                '''
                INSERT INTO products (
                    product_name, category_id, subcategory_id, category_group_id, sku, supplier_id, unit_id, quantity_in_stock, reorder_level, purchase_price, selling_price
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (product_name, category_id, subcategory_id, category_group_id, sku, supplier_id, unit_id, quantity_in_stock, reorder_level, purchase_price, selling_price)
            )
            conn.commit()
            conn.close()

            flash("Product added successfully!", "success")
            return redirect(url_for("add_product"))

        except sqlite3.IntegrityError:
            flash("SKU already exists. Please use a unique SKU.", "danger")
            return redirect(url_for("add_product"))
        
    # ✅ Fetch categories, units and subcategories for dropdowns
    categories = conn.execute("SELECT id, category_name FROM categories").fetchall()
    subcategories = conn.execute("SELECT id, subcategory_name FROM subcategories").fetchall()
    categoriesgroups = conn.execute("SELECT id, group_name FROM categoriesgroups").fetchall()
    units = conn.execute("SELECT id, unit_name, abbreviation FROM units").fetchall()

    conn.close()

    return render_template("add_product.html", categories=categories, subcategories=subcategories, categoriesgroups=categoriesgroups, units=units)

# Fetch subcategories based on category
@app.route('/get_subcategories/<int:category_id>')
@login_required("admin")
def get_subcategories(category_id):
    conn = get_db_connection()
    subcategories = conn.execute(
        "SELECT id, subcategory_name FROM subcategories WHERE category_id = ?", 
        (category_id,)
    ).fetchall()
    conn.close()
    return jsonify([{"id": s["id"], "name": s["subcategory_name"]} for s in subcategories])

# Fetch category groups based on subcategory
@app.route('/get_category_groups/<int:subcategory_id>')
@login_required("admin")
def get_category_groups(subcategory_id):
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row 
    groups = conn.execute(
        "SELECT id, group_name FROM categoriesgroups WHERE subcategory_id = ?", 
        (subcategory_id,)
    ).fetchall()
    conn.close()
    return jsonify([{"id": g["id"], "name": g["group_name"]} for g in groups])

# Route for Stock Catalog
@app.route('/stock_catalog', methods=['GET'])
@login_required()
def stock_catalog():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM products')
        products = cursor.fetchall()
    except Exception as e:
        flash(f'Error loading stock catalog: {e}', 'danger')
        products = []
    finally:
        conn.close()

    return render_template('stock_catalog.html', stock=products)

# Route for Edit Product
@app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
@login_required("admin", "manager")
def edit_product(product_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Fetch the product to pre-fill the form
        cursor.execute('SELECT * FROM products WHERE id = ?', (product_id,))
        product = cursor.fetchone()
        if not product:
            flash('Product not found.', 'danger')
            return redirect(url_for('stock_catalog'))

        if request.method == 'POST':
            product_name = request.form.get('product_name').strip()
            product_category = request.form.get('product_category').strip()
            product_subcategory = request.form.get('product_subcategory').strip()
            selling_price = float(request.form.get('selling_price'))
            quantity_in_stock = int(request.form.get('quantity_in_stock'))

            cursor.execute('''
                UPDATE products
                SET product_name = ?,product_category = ?, product_subcategory = ?, selling_price = ?, quantity_in_stock = ?
                WHERE id = ?
            ''', (product_name, product_category, product_subcategory, selling_price, quantity_in_stock, product_id))
            conn.commit()

            flash('Product updated successfully!', 'success')
            return redirect(url_for('stock_catalog'))

    except Exception as e:
        flash(f'Error editing product: {e}', 'danger')
        return redirect(url_for('stock_catalog'))
    finally:
        conn.close()

    return render_template('edit_product.html', product=product)

# Route for Delete Product
@app.route('/delete_product/<int:product_id>', methods=['POST'])
@login_required("admin", "manager")
def delete_product(product_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT * FROM products WHERE id = ?', (product_id,))
        product = cursor.fetchone()
        if not product:
            flash('Product not found.', 'danger')
            return redirect(url_for('stock_catalog'))

        cursor.execute('DELETE FROM products WHERE id = ?', (product_id,))
        conn.commit()
        flash('Product deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting product: {e}', 'danger')
    finally:
        conn.close()

    return redirect(url_for('stock_catalog'))


# Route for Restocking Products
@app.route('/restock', methods=['GET', 'POST'])
@login_required("admin", "manager")
def restock():
    if request.method == "POST":
        sku = request.form.get("sku").strip()
        quantity = int(request.form.get("quantity"))

        if quantity <= 0:
            flash("Quantity must be greater than 0", "danger")
            return redirect(url_for("restock"))

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, product_name, quantity_in_stock FROM products WHERE sku = ?", (sku,))
        product = cursor.fetchone()

        if not product:
            conn.close()
            flash("Product with this SKU not found.", "danger")
            return redirect(url_for("restock"))

        # ✅ Update stock
        cursor.execute("""
            UPDATE products
            SET quantity_in_stock = quantity_in_stock + ?
            WHERE id = ?
        """, (quantity, product["id"]))
        conn.commit()
        conn.close()

        flash(f"Restocked {quantity} units of {product['product_name']} (SKU: {sku})", "success")
        return redirect(url_for("stock_catalog"))

    # ✅ Fixed return statement
    return render_template("restock.html")


# Route for Add Sales
@app.route("/add_sales", methods=["GET", "POST"])
@login_required("admin", "manager", "staff")
def add_sales():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch products & customers for dropdowns
    cursor.execute("SELECT id, product_name, quantity_in_stock, selling_price FROM products")
    products = cursor.fetchall()

    cursor.execute("SELECT id, customer_name FROM customers")
    customers = cursor.fetchall()

    if request.method == "POST":
        customer_id = request.form.get("customer_id")  # dropdown gives id
        payment_method = request.form.get("payment_method")
        invoice_number = generate_invoice_number()

        # Get date from form
        sale_date_str = request.form['invoice_date']
        sale_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S") # convert to datetime

        # ✅ Fetch customer name from DB using customer_id
        cursor.execute("SELECT customer_name FROM customers WHERE id = ?", (customer_id,))
        customer_row = cursor.fetchone()
        customer_name = customer_row["customer_name"] if customer_row else "Unknown"

        product_ids = request.form.getlist("product_id[]")
        quantities = request.form.getlist("quantity[]")

        total_amount = 0
        sale_items = []

        for pid, qty in zip(product_ids, quantities):
            if not pid or not qty.strip():
                continue
            qty = int(qty)

            cursor.execute("SELECT quantity_in_stock, selling_price FROM products WHERE id = ?", (pid,))
            product_data = cursor.fetchone()
            if not product_data:
                flash(f"Product ID {pid} not found.", "error")
                conn.close()
                return redirect(url_for("add_sales"))

            stock = product_data["quantity_in_stock"]
            unit_price = product_data["selling_price"]

            if qty <= 0:
                flash("Quantity must be greater than zero.", "error")
                conn.close()
                return redirect(url_for("add_sales"))

            if qty > stock:
                flash(f"Not enough stock for product ID {pid}. Available: {stock}", "error")
                conn.close()
                return redirect(url_for("add_sales"))

            total_price = qty * unit_price
            total_amount += total_price
            sale_items.append((pid, qty, unit_price, total_price))

        if not sale_items:
            flash("Please add at least one product.", "error")
            conn.close()
            return redirect(url_for("add_sales"))

        # Insert into sales
        cursor.execute('''
            INSERT INTO sales (invoice_number, customer_id, sale_date, total_amount, payment_method)
            VALUES (?, ?, ?, ?, ?)
        ''', (invoice_number, customer_id, sale_date, total_amount, payment_method))
        sale_id = cursor.lastrowid

        # ✅ Insert into invoices with customer_name
        cursor.execute('''
            INSERT INTO invoices (invoice_number, customer_name, total_amount, invoice_date, created_by)
            VALUES (?, ?, ?, datetime('now','localtime'), ?)
        ''', (invoice_number, customer_name, total_amount, session["user_id"]))
        invoice_id = cursor.lastrowid  

        # Insert items + update stock
        for pid, qty, price, total_price in sale_items:
            cursor.execute('''
                INSERT INTO sales_items (sale_id, product_id, quantity, unit_price, total_price)
                VALUES (?, ?, ?, ?, ?)
            ''', (sale_id, pid, qty, price, total_price))

            # invoice_items entry
            cursor.execute('''
                INSERT INTO invoice_items (invoice_id, product_id, quantity, unit_price, total_price)
                VALUES (?, ?, ?, ?, ?)
            ''', (invoice_id, pid, qty, price, total_price))

            cursor.execute('''
                UPDATE products
                SET quantity_in_stock = quantity_in_stock - ?
                WHERE id = ?
            ''', (qty, pid))

        conn.commit()
        conn.close()

        flash(f"Sale recorded successfully! Invoice: {invoice_number}", "success")
        return redirect(url_for("add_sales"))

    conn.close()
    return render_template("add_sales.html", products=products, customers=customers)



# Route for Sales Sight
@app.route('/sales_sight', methods=['GET'])
@login_required()
def sales_sight():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT s.id,
            s.invoice_number,
            s.sale_date,
            c.customer_name,
            s.total_amount,
            s.payment_method,
            GROUP_CONCAT(p.product_name || ' (x' || total_q.qty || ')', ', ') AS products
        FROM sales s
        LEFT JOIN customers c ON s.customer_id = c.id
        LEFT JOIN (
            SELECT si.sale_id, si.product_id, SUM(si.quantity) AS qty
            FROM sales_items si
            GROUP BY si.sale_id, si.product_id
        ) AS total_q ON s.id = total_q.sale_id
        LEFT JOIN products p ON total_q.product_id = p.id
        GROUP BY s.id
        ORDER BY s.invoice_number DESC
    ''')

    sales = cursor.fetchall()
    conn.close()

    return render_template("sales_sight.html", sales=sales)

# Route for Customer
@app.route("/customers", methods=["GET", "POST"])
@login_required()
def customers():
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == "POST":
        customer_name = (request.form.get("customer_name") or "").strip()
        contact_number = (request.form.get("contact_number") or "").strip()
        email = (request.form.get("email") or "").strip()

        if not customer_name:
            flash("Customer name is required.", "error")
            return redirect(url_for("customers"))
        
        if not contact_number and not email:
            flash("At least one contact method (phone or email) is required.", "error")
            return redirect(url_for("customers"))

        # Insert customer into database
        cursor.execute('''
            INSERT INTO customers (customer_name, contact_number, email, created_at)
            VALUES (?, ?, ?, ?)
        ''', (customer_name, contact_number, email, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

        conn.commit()
        flash("Customer added successfully!", "success")
        conn.close()
        return redirect(url_for("customers"))

    # Fetch all customers
    cursor.execute("SELECT * FROM customers ORDER BY id DESC")
    customers_list = cursor.fetchall()

    conn.close()
    return render_template("customers.html", customers=customers_list)

@app.route("/delete_customer/<int:id>", methods=["POST"])
@login_required("admin", "manager")
def delete_customer(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM customers WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    flash("Customer deleted successfully!", "success")
    return redirect(url_for("customers"))


# Route for Reports
@app.route('/reports')
@login_required()
def reports():
    conn = get_db_connection()

    # current_datetime = datetime.now().strftime('%d-%m-%Y %H:%M:%S %p')  # e.g., 01-09-2025 23:15:42

    # Get logged-in user info from session
    user_name = session.get('username')
    user_role = session.get('role')

    # Total Sales (count of invoices)
    total_sales = conn.execute("SELECT COUNT(*) FROM invoices").fetchone()[0]

    # Total Products (count of products)
    total_products = conn.execute("SELECT COUNT(*) FROM products").fetchone()[0]

    # Total Customers (count of customers)
    total_customers = conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0]

    # Low Stock Products (count of products below reorder level)
    low_stock_items = conn.execute("SELECT COUNT(*) FROM products WHERE quantity_in_stock <= reorder_level").fetchone()[0]

    # Total Revenue (sum of amounts)
    total_revenue = conn.execute("SELECT COALESCE(SUM(total_amount), 0) FROM invoices").fetchone()[0]

    # Today's Sales
    today_sales = conn.execute('''
        SELECT COUNT(*) FROM invoices
        WHERE DATE(invoice_date) = DATE('now', 'localtime')
    ''').fetchone()[0] or 0

    # Today's Revenue
    today_revenue = conn.execute('''
        SELECT COALESCE(SUM(total_amount), 0) FROM invoices
        WHERE DATE(invoice_date) = DATE('now', 'localtime')
    ''').fetchone()[0] or 0

    # Recent Stock Additions (last 5 products added)
    recent_stock = conn.execute('''
        SELECT p.product_name, 
            c.category_name,
            sc.subcategory_name,
            p.supplier_id, 
            u.unit_name, 
            p.quantity_in_stock,
            p.purchase_price,
            p.reorder_level   -- ✅ include reorder_level
        FROM products p
        LEFT JOIN categories c ON p.category_id = c.id
        LEFT JOIN subcategories sc ON p.subcategory_id = sc.id
        LEFT JOIN suppliers s ON p.supplier_id = s.id
        LEFT JOIN units u ON p.unit_id = u.id
        ORDER BY p.id DESC   -- ✅ use ID instead of created_at
        LIMIT 5
    ''').fetchall()

    # Recent Sales (last 5 invoices)
    recent_sales = conn.execute('''
        SELECT s.invoice_number, 
            c.customer_name, 
            s.sale_date, 
            GROUP_CONCAT(p.product_name, ', ') as products,  -- ✅ join to show product names
            SUM(si.quantity) as quantity,
            s.total_amount
        FROM sales s
        LEFT JOIN customers c ON s.customer_id = c.id
        LEFT JOIN sales_items si ON s.id = si.sale_id
        LEFT JOIN products p ON si.product_id = p.id
        GROUP BY s.id
        ORDER BY s.sale_date DESC
        LIMIT 5
    ''').fetchall()

    # Recent Customers (last 5 customers added)
    recent_customers = conn.execute('''
        SELECT c.customer_name, 
            c.contact_number, 
            c.email,
            IFNULL(SUM(s.total_amount), 0) as total_purchases,
            MAX(s.sale_date) as last_purchase
        FROM customers c
        LEFT JOIN sales s ON c.id = s.customer_id
        GROUP BY c.id
        ORDER BY c.id DESC   -- ✅ use ID instead of created_at
        LIMIT 5
    ''').fetchall()

    # Top Customers (use customer_name instead of customer_id)
    top_customers = conn.execute('''
        SELECT i.customer_name, SUM(i.total_amount) as total_spent
        FROM invoices i
        GROUP BY i.customer_name
        ORDER BY total_spent DESC
        LIMIT 3
    ''').fetchall()

    # Best-Selling Products
    best_products = conn.execute('''
        SELECT p.product_name, SUM(ii.quantity) as total_sold
        FROM invoice_items ii
        JOIN products p ON ii.product_id = p.id
        GROUP BY ii.product_id
        ORDER BY total_sold DESC
        LIMIT 2
    ''').fetchall()

    conn.close()

    return render_template('reports.html',
                           total_sales=total_sales,
    total_revenue=total_revenue,
    recent_customers=recent_customers,
    recent_sales=recent_sales,
    recent_stock=recent_stock,
    total_products=total_products,
    total_customers=total_customers,
    low_stock_items=low_stock_items,
    today_sales=today_sales,
    today_revenue=today_revenue,
    user_name=user_name,
    user_role=user_role)



# 📂 Route for Export CSV
@app.route('/export_csv')
@login_required()
def export_csv():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sales")
    rows = cursor.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([i[0] for i in cursor.description])  # Header
    for row in rows:
        writer.writerow(row)

    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode('utf-8')),
                     mimetype="text/csv",
                     as_attachment=True,
                     download_name=f"reports_{datetime.now().strftime('%Y%m%d')}.csv")

# 📂 Route for Export PDF
@app.route("/export_pdf")
@login_required()
def export_pdf():
    buffer = io.BytesIO()

    # --- Fetch data from DB ---
    conn = sqlite3.connect("shelfsmart.db")
    cursor = conn.cursor()

    cursor.execute("SELECT SUM(total_amount) FROM sales")
    total_sales = cursor.fetchone()[0] or 0

    cursor.execute("SELECT SUM(quantity) FROM sales_items")
    total_items_sold = cursor.fetchone()[0] or 0

    cursor.execute("SELECT COUNT(*) FROM customers")
    total_customers = cursor.fetchone()[0] or 0

    cursor.execute("SELECT SUM(quantity_in_stock * purchase_price) FROM products")
    total_stock_value = cursor.fetchone()[0] or 0

    cursor.execute('''
        SELECT c.customer_name, SUM(s.total_amount) as total_spent
        FROM sales s
        JOIN customers c ON s.customer_id = c.id
        GROUP BY c.id
        ORDER BY total_spent DESC
        LIMIT 5
    ''')
    top_customers = cursor.fetchall()

    cursor.execute('''
        SELECT p.product_name, SUM(si.quantity) as total_qty
        FROM sales_items si
        JOIN products p ON si.product_id = p.id
        GROUP BY p.id
        ORDER BY total_qty DESC
        LIMIT 5
    ''')
    best_products = cursor.fetchall()

    conn.close()

    # --- Helper to add page numbers ---
    def add_page_number(canvas, doc):
        page_num = canvas.getPageNumber()
        canvas.setFont('Times-Roman', 9)
        text = f"{page_num}"

        # Position: bottom center
        canvas.drawCentredString(
            doc.pagesize[0] / 2.0,   # X = center of the page
            0.3 * inch,              # Y = 0.5 inch from bottom
            text
        )

    # --- Helper to add watermark ---
    def add_watermark(canvas, doc):
        canvas.saveState()
        canvas.setFont('Times-Bold', 50)
        canvas.setFillColorRGB(0.9, 0.9, 0.9, alpha=0.3)  # Light gray transparent
        canvas.translate(300, 400)
        canvas.rotate(45)
        canvas.drawCentredString(0, 0, "CONFIDENTIAL")
        canvas.restoreState()

    # Footer function
    def add_footer(canvas, doc):
        current_time = datetime.now().strftime('%d-%m-%Y %H:%M:%S')
        footer_text = f"Generated on: {current_time}"
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.grey)
        canvas.drawString(40, 20, footer_text)  # (x, y) position from bottom-left
        canvas.restoreState()

    # Combined functions for first page
    def first_page(canvas, doc):
        add_watermark(canvas, doc)
        add_page_number(canvas, doc)
        add_footer(canvas, doc)

    # Combined functions for later pages
    def later_pages(canvas, doc):
        add_watermark(canvas, doc)
        add_page_number(canvas, doc)
        add_footer(canvas, doc)


    # --- Generate PDF ---
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        title="ShelfSmart Report",
        author="ShelfSmart App",
        rightMargin=30, leftMargin=30, topMargin=50, bottomMargin=40
    )
    story = []

    # Styles
    title_style = ParagraphStyle('Title', fontName='Times-Bold', fontSize=20, alignment=TA_CENTER, spaceAfter=15)
    subtitle_style = ParagraphStyle('Subtitle', fontName='Times-Bold', fontSize=14, alignment=TA_CENTER, textColor=colors.HexColor("#555555"), spaceAfter=20)

    # # Logo
    # logo = Image("static/icons/ShelfSmart (1).png", width=80, height=80)
    # logo.hAlign = 'CENTER'
    # story.append(logo)
    # story.append(Spacer(1, 10))

    # company_name = "ShelfSmart Pvt Ltd."
    # company_address = "123, Tech Street, Erode"
    # company_contact = "contact@shelfsmart.com | +91 98765 43210"

    # story.append(Paragraph(company_name, ParagraphStyle('CompanyName', fontSize=16, alignment=TA_CENTER, textColor=colors.HexColor("#333333"), spaceAfter=10)))
    # story.append(Paragraph(company_address, ParagraphStyle('CompanyAddress', fontSize=10, alignment=TA_CENTER, textColor=colors.HexColor("#555555"), spaceAfter=5)))
    # story.append(Paragraph(company_contact, ParagraphStyle('CompanyContact', fontSize=10, alignment=TA_CENTER, textColor=colors.HexColor("#555555"))))
    # story.append(Spacer(1, 60))


    # Title, logo and Prepared by
    logo = Image("static/icons/shelfsmart_crop.png", width=80, height=80)
    logo.hAlign = 'CENTER'
    
    report_title = "ShelfSmart Report"
    prepared_by = "Admin / Manager"

    story.append(Spacer(1, 220))  # Push content down for cover page
    story.append(logo)
    story.append(Paragraph(report_title, title_style))
    story.append(Paragraph(f"Prepared by: {prepared_by}", subtitle_style))
    story.append(Paragraph(f"Date: {datetime.now().strftime('%d-%m-%Y %H:%M')}", subtitle_style))
    story.append(PageBreak())  # Start main content on a new page


    overview_title = "Statistics Overview and Insights"
    story.append(Paragraph(overview_title, ParagraphStyle('OverviewTitle', fontName='Times-Bold', fontSize=24, alignment=TA_CENTER, textColor=colors.HexColor("#010101"), spaceAfter=20)))
    story.append(Spacer(1, 30))

    # Summary Table
    summary_data = [["Metric", "Value"], ["Total Sales", total_sales], ["Total Items Sold", total_items_sold], ["Total Customers", total_customers], ["Total Stock Value", total_stock_value]]
    summary_table = Table(summary_data, hAlign='CENTER', colWidths=[250, 150])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#4C6EF5")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME', (0,0), (-1,0), 'Times-Bold'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 35))

    # Top Customers Table
    story.append(Paragraph("Top Customers", subtitle_style))

    if top_customers:
        top_customer_data = [["Customer", "Total Spent"]] + [[c[0], c[1]] for c in top_customers]
    else:
        top_customer_data = [["Customer", "Total Spent"], ["No customer data available", "N/A"]]

    customer_table = Table(top_customer_data, hAlign='CENTER', colWidths=[250, 150])
    customer_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1ABC9C")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME', (0,0), (-1,0), 'Times-Bold'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(customer_table)
    story.append(Spacer(1, 35))

    # Best-Selling Products Table
    story.append(Paragraph("Best-Selling Products", subtitle_style))
    if best_products:
        product_data = [["Product", "Quantity Sold"]] + [[p[0], p[1]] for p in best_products]
    else:
        product_data = [["Product", "Quantity Sold"], ["No product data available", "N/A"]]

    product_table = Table(product_data, hAlign='CENTER', colWidths=[250, 150])
    product_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#F39C12")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME', (0,0), (-1,0), 'Times-Bold'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(product_table)
    story.append(Spacer(1, 35))


    # Build PDF
    doc.build(story, onFirstPage=first_page, onLaterPages=later_pages)

    buffer.seek(0)

    # Send PDF as response
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"reports_{datetime.now().strftime('%d-%m-%Y %H:%M:%S')}.pdf",
        mimetype="application/pdf"
    )


if __name__ == '__main__':
    create_tables()  # Ensure tables are created at startup
    app.run(debug=True)

