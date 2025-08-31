from flask import Flask, render_template, request, redirect, send_file, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import sqlite3
import csv
import io
from reportlab.platypus import Image
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER , TA_LEFT
from reportlab.lib import colors

app = Flask(__name__, template_folder='templates')
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
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=1)  # optional timeout


def create_tables():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Users table
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

    # Products table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_name TEXT NOT NULL,
            product_category TEXT NOT NULL,
            sku TEXT NOT NULL UNIQUE,
            supplier_id INTEGER,
            measurement_unit TEXT NOT NULL,
            quantity_in_stock INTEGER DEFAULT 0 NOT NULL,
            reorder_level INTEGER DEFAULT 0 NOT NULL,
            purchase_price REAL NOT NULL,
            selling_price REAL NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Sales table
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

    # Sales Items table
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

    # Invoices table
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

    # Invoice Items table
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

    # Customers table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_name TEXT NOT NULL,
            contact_number TEXT NOT NULL,
            email TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
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

# Route for Dashboard
@app.route('/dashboard')
@login_required()
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access the dashboard.', 'danger')
        return redirect(url_for('login'))

    role = session.get('role')
    username = session.get('username')

    # Common stats for all roles
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT COUNT(*) FROM products")
        total_products = cursor.fetchone()[0] or 0

        cursor.execute("SELECT COUNT(*) FROM customers")
        total_customers = cursor.fetchone()[0] or 0

        cursor.execute('''SELECT COALESCE(SUM(total_amount), 0) FROM sales WHERE DATE(sale_date) = DATE('now', 'localtime')''')
        today_sales = cursor.fetchone()[0]


        cursor.execute("SELECT COALESCE(SUM(total_amount), 0) FROM sales")
        total_sales = cursor.fetchone()[0] or 0

    except Exception as e:
        flash(f"Error loading dashboard data: {e}", "danger")
        total_products = total_customers = today_sales = total_sales = 0
    finally:
        conn.close()

    return render_template('dashboard.html', username=username, role=role, total_products=total_products, total_customers=total_customers, today_sales=today_sales, total_sales=total_sales)



# Route for Add Products
@app.route('/add_product', methods=['GET', 'POST'])
@login_required("admin", "manager")
def add_product():
    if request.method == "POST":
        product_name = request.form["product_name"]
        product_category = request.form["product_category"]
        sku = request.form["sku"]
        supplier_id = request.form["supplier_id"]
        measurement_unit = request.form["measurement_unit"]
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
                """
                INSERT INTO products (
                    product_name, product_category, sku, supplier_id, measurement_unit, quantity_in_stock, reorder_level, purchase_price, selling_price
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (product_name, product_category, sku, supplier_id, measurement_unit, quantity_in_stock, reorder_level, purchase_price, selling_price)
            )
            conn.commit()
            conn.close()

            flash("Product added successfully!", "success")
            return redirect(url_for("add_product"))

        except sqlite3.IntegrityError:
            flash("SKU already exists. Please use a unique SKU.", "danger")
            return redirect(url_for("add_product"))

    return render_template("add_product.html")

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
            selling_price = float(request.form.get('selling_price'))
            quantity_in_stock = int(request.form.get('quantity_in_stock'))

            cursor.execute('''
                UPDATE products
                SET product_name = ?,product_category = ?, selling_price = ?, quantity_in_stock = ?
                WHERE id = ?
            ''', (product_name, product_category, selling_price, quantity_in_stock, product_id))
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
        sale_date = datetime.strptime(sale_date_str, "%Y-%m-%d") # convert to datetime

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

    # Total Sales (count of invoices)
    total_sales = conn.execute("SELECT COUNT(*) FROM invoices").fetchone()[0]

    # Total Revenue (sum of amounts)
    total_revenue = conn.execute("SELECT COALESCE(SUM(total_amount), 0) FROM invoices").fetchone()[0]

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
                           top_customers=top_customers,
                           best_products=best_products)



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

# 📄 Route for Export PDF
@app.route("/export_pdf")
@login_required()
def export_pdf():
    conn = sqlite3.connect("shelfsmart.db")
    cursor = conn.cursor()

    # --- Fetch totals ---
    cursor.execute("SELECT SUM(total_amount) FROM sales")
    total_sales = cursor.fetchone()[0] or 0

    cursor.execute("SELECT SUM(quantity) FROM sales_items")
    total_items_sold = cursor.fetchone()[0] or 0

    cursor.execute("SELECT COUNT(*) FROM customers")
    total_customers = cursor.fetchone()[0] or 0

    # --- Top Customers ---
    cursor.execute('''
        SELECT c.customer_name, SUM(s.total_amount) as total_spent
        FROM sales s
        JOIN customers c ON s.customer_id = c.id
        GROUP BY c.id
        ORDER BY total_spent DESC
        LIMIT 5
    ''')
    top_customers = cursor.fetchall()

    # --- Best-Selling Products ---
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

    # Function to add page numbers
    def add_page_number(canvas, doc):
        page_num_text = f"Page {doc.page}"
        canvas.saveState()
        canvas.setFont('Times-Roman', 10)
        canvas.drawRightString(300, 20, page_num_text)  # Adjust position (x=right, y=bottom)
        canvas.restoreState()

    # --- PDF Generation ---

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, title="ShelfSmart Sales Report", author="ShelfSmart App", rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    story = []

    # Styles
    title_style = ParagraphStyle('Title', fontName='Times-Bold', fontSize=20, alignment=TA_CENTER, spaceAfter=20)
    table_header_style = ParagraphStyle('TableHeader', fontName='Times-Bold', fontSize=12, alignment=TA_CENTER)
    table_data_style = ParagraphStyle('TableData', fontName='Times', fontSize=11, alignment=TA_CENTER)


    # Logo
    logo = Image("static/icons/round1.png", width=50, height=50)
    logo.hAlign = 'CENTER'
    story.append(logo)
    story.append(Spacer(1, 10))

    # Title
    story.append(Paragraph("ShelfSmart - Sales Report", title_style))
    story.append(Spacer(1, 20))

    # Summary Table
    summary_data = [["Metric", "Value"],
                    ["Total Sales", total_sales],
                    ["Total Items Sold", total_items_sold],
                    ["Total Customers", total_customers]]

    summary_table = Table(summary_data, hAlign='CENTER', colWidths=[250, 150])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#9bcfea")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.black),
        ('GRID', (0,0), (-1,-1), 0.6, colors.grey),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME', (0,0), (-1,0), 'Times-Bold'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 20))

    # Top Customers Table
    story.append(Paragraph("Top Customers", title_style))
    top_customer_data = [["Customer", "Total Spent"]] + [[c[0], c[1]] for c in top_customers]
    customer_table = Table(top_customer_data, hAlign='CENTER', colWidths=[250, 150])
    customer_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#b1e79c")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.black),
        ('GRID', (0,0), (-1,-1), 0.6, colors.grey),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME', (0,0), (-1,0), 'Times-Bold'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(customer_table)
    story.append(Spacer(1, 20))

    # Best-Selling Products Table
    story.append(Paragraph("Best-Selling Products", title_style))
    product_data = [["Product", "Quantity Sold"]] + [[p[0], p[1]] for p in best_products]
    product_table = Table(product_data, hAlign='CENTER', colWidths=[250, 150])
    product_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#EBD279")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.black),
        ('GRID', (0,0), (-1,-1), 0.6, colors.grey),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME', (0,0), (-1,0), 'Times-Bold'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(product_table)

    # Build PDF with page number
    doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)
    buffer.seek(0)

    # Send the PDF as a response
    return send_file(buffer, as_attachment=True, download_name=f"reports_{datetime.now().strftime('%Y%m%d')}.pdf", mimetype="application/pdf")


if __name__ == '__main__':
    create_tables()  # Ensure tables are created at startup
    app.run(debug=True)

