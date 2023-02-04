import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    username = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0]["username"]
    stocks = db.execute("SELECT symbol, shares FROM portfolio WHERE username = ?", username)

    # Create a list to store total prices of each stock
    stock_totals = []

    # Iterate through all rows in stocks and add sum in stock_totals
    for stock in stocks:
        symbol = stock["symbol"]
        shares = int(stock["shares"])
        name = lookup(symbol)["name"]
        price = lookup(symbol)["price"]
        total = shares * price
        stock["name"] = name
        stock["price"] = price
        stock["total"] = total
        stock_totals.append(total)

    # extract current remaining cash amount and add to stock_totals
    balance_cash = db.execute("SELECT cash FROM users WHERE username = ?", username)[0]["cash"]

    grand_total = balance_cash + sum(stock_totals)

    return render_template("index.html", stocks=stocks, balance_cash=balance_cash, grand_total=grand_total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        stock = lookup(symbol)

        # Ensure symbol and shares are submitted
        if not symbol:
            return apology("must provide symbol", 400)

        # Ensure symbol is valid
        if stock == None:
            return apology("symbol not valid", 400)

        if not shares or shares.isdigit() == False:
            return apology("must provide valid number of shares", 400)

        # Ensure number of shares is a positive integer
        if int(shares) < 1:
            return apology("number of shares must be a positive integer", 400)

        # Store transaction type as 'Bought'
        type = "Bought"

        username = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0]["username"]

        total_price = int(shares) * stock.get("price")

        # extract remaining balance cash in user cash column
        account_balance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])

        if total_price > account_balance[0]["cash"]:
            return apology("sorry, you cannot afford this number of shares at the current price", 403)

        else:
            # Enter record in history table
            db.execute("INSERT INTO history (username, type, symbol, companyName, shares, price, time) VALUES(?, ?, ?, ?, ?, ?, ?)",
                       username, type, symbol, stock.get("name"), shares, stock.get("price"), datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

            # Update username table with cash value
            db.execute("UPDATE users SET cash = cash - (? * ?) WHERE id = ?", stock.get("price"), shares, session["user_id"])

            # update user's portfolio for existing stock records
            rows = db.execute("SELECT * FROM portfolio WHERE symbol = ?", symbol)

            # If same stock already bought before, update the share value, else create new row
            if len(rows) != 0:
                db.execute("UPDATE portfolio SET shares = shares + ? WHERE symbol = ?", shares, symbol)
            else:
                db.execute("INSERT INTO portfolio (username, symbol, shares, price) VALUES(?, ?, ?, ?)",
                           username, symbol, shares, stock.get("price"))

        flash("Bought!")

        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # Extract username from users
    username = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0]["username"]

    # extract stock list of user with matching username
    stocks = db.execute("SELECT * FROM history WHERE username = ?", username)

    # if no transaction happened yet, display message
    if len(stocks) == 0:
        return apology("sorry you have no transactions to display", 403)

    # display history.html table
    return render_template("history.html", stocks=stocks)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 400)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        quoted = lookup(symbol)

        # if invalid symbol, display message
        if quoted == None:
            return apology("Invalid symbol", 400)
        else:
            # take user to show current price of required stock
            return render_template("quoted.html", quoted=quoted)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        username = request.form.get("username")
        hash = generate_password_hash(request.form.get("password"))

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure password was submitted
        if not request.form.get("confirmation"):
            return apology("must re-enter password", 400)

        # check for plain text passwords
        # Inspired by https://www.ibm.com/docs/en/baw/20.x?topic=security-characters-that-are-valid-user-ids-passwords
        special_chars = ["!", "(", ")", "-", ".", "?", "[", "]", "_", "~", ";", ":", "@", "#", "$", "%", "^", "&", "*", "+", "="]

        if request.form.get("password").isalpha():
            return apology("password must contain at least one numeric and one special character", 400)

        char_count = 0
        for char in special_chars:
            if char in request.form.get("password"):
                char_count += 1

        if char_count == 0:
            return apology("password must contain at least one numeric and one special character", 400)

        # Check password matches the confirmation password
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("password and confirmation do not match", 400)

        # Ensure username is not already registered in database
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        if len(rows) != 0:
            return apology("username already taken", 400)

        # Insert user into database
        result = db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hash)

        # Remember registered user
        session["user_id"] = result

        flash("Registered!")

        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/change password", methods=["GET", "POST"])
def change_pass():
    """Change user password"""

    # User reached route via POST (as by clicking the 'Change Password' button)
    if request.method == "POST":
        current_pass = request.form.get("current_password")

        if not request.form.get("new_password"):
            return apology("please enter new password", 400)

        if not request.form.get("confirmation"):
            return apology("enter new password again", 400)

        if request.form.get("new_password") != request.form.get("confirmation"):
            return apology("password and confirmation do not match", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

        # Ensure username exists and current password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], current_pass):
            return apology("invalid username and/or password", 400)

        new_hash = generate_password_hash(request.form.get("new_password"))

        db.execute("UPDATE users SET hash = ? WHERE id = ?", new_hash, session["user_id"])

        flash("Password changed successfully!")

        return redirect("/")

    else:
        return render_template("change_pass.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # Extract username from users
    username = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])[0]["username"]

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        stock = lookup(symbol)

        # Ensure symbol and shares are submitted
        if not symbol:
            return apology("must provide symbol", 400)

        # Ensure symbol is valid
        if stock == None:
            return apology("symbol not valid", 400)

        if not shares or shares.isdigit() == False:
            return apology("must provide number of shares", 400)

        # Ensure number of shares is a positive integer
        if int(shares) <= 0:
            return apology("number of shares must be a positive integer", 400)

        # store transaction type as 'Sold'
        type = "Sold"

        # Extract current number of shares withheld by user
        existing_shares = db.execute("SELECT shares FROM portfolio WHERE symbol = ? AND username = ?", symbol, username)

        if int(shares) > existing_shares[0]["shares"]:
            return apology("not sufficient shares available to sell", 400)

        # If user selling all shares, delete the stock from portfolio, else update the record
        if int(shares) == existing_shares[0]["shares"]:
            # Enter record in history table
            db.execute("INSERT INTO history (username, type, symbol, companyName, shares, price, time) VALUES(?, ?, ?, ?, ?, ?, ?)",
                       username, type, symbol, stock.get("name"), shares, stock.get("price"), datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

            # Update username table with cash value
            db.execute("UPDATE users SET cash = cash + (? * ?) WHERE id = ?", stock.get("price"), shares, session["user_id"])

            db.execute("DELETE FROM portfolio WHERE symbol = ? AND username = ?", symbol, username)

        else:
            # Enter record in history table
            db.execute("INSERT INTO history (username, type, symbol, companyName, shares, price, time) VALUES(?, ?, ?, ?, ?, ?, ?)",
                       username, type, symbol, stock.get("name"), shares, stock.get("price"), datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

            # Update username table with cash value
            db.execute("UPDATE users SET cash = cash + (? * ?) WHERE id = ?", stock.get("price"), shares, session["user_id"])

            db.execute("UPDATE portfolio SET shares = shares - ? WHERE symbol = ? AND username = ?", shares, symbol, username)

        flash("Sold!")

        # Redirect user to home page
        return redirect("/")

    else:
        symbols = db.execute("SELECT symbol FROM portfolio WHERE username = ?", username)

        return render_template("sell.html", symbols=symbols)