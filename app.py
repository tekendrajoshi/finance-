import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

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
    user_id=session["user_id"]
    stocks= db.execute("SELECT symbol, name, price, SUM(shares) as totalShares FROM transactions WHERE user_id=? GROUP BY symbol",user_id)
    cash= db.execute("SELECT cash FROM users WHERE id =?", user_id)[0]["cash"]
    total=cash
    for stock in stocks:
        total += stock["price"]* stock["totalShares"]

    return render_template("index.html", stocks=stocks, cash=cash, usd=usd, total=total)



@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method=="POST":
        symbol=request.form.get("symbol").upper()
        item=lookup(symbol)
        if not symbol:
            return apology("Enter symbol!")
        elif not item:
            return apology("Invalid symbol!")
        try:
            shares=int(request.form.get("shares"))
        except:
            return apology("Shares must be an integer!")
        if shares<=0:
            return apology("Shares must be positive integer!")

        user_id= session["user_id"]
        cash=db.execute("SELECT cash FROM users WHERE id=?", user_id)[0]["cash"]

        item_name= item["name"]
        item_price= item["price"]
        total_price= item_price * shares

        if cash < total_price:
            return apology("Insufficient cash")
        else:
            db.execute("UPDATE users SET cash= ? WHERE id= ?", cash - total_price, user_id)
            db.execute("INSERT INTO transactions(user_id, name, shares, price, type, symbol) VALUES(?, ?, ?, ?, ?, ?)",user_id, item_name, shares, item_price, 'buy', symbol)

        return redirect('/')


    else:
        return render_template("buy.html")

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id= session["user_id"]
    items= db.execute("SELECT type, symbol, price, shares, time FROM transactions WHERE user_id=?", user_id)
    return render_template("history.html", items= items)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

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
    if request.method  == "POST":
        symbol= request.form.get('symbol')
        if not symbol:
            return apology("Please enter a symbol")
        item= lookup(symbol)
        if not item:
            return apology("The symbol doesnt match!")
        return render_template("quoted.html", item=item, usd=usd) # we can even pass the function to the template
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method=="POST":
        username= request.form.get('username')
        password= request.form.get('password')
        confirmation= request.form.get('confirmation')

        if not username:
            return apology("Username not found")
        elif not password:
            return apology("Password not found")
        elif not confirmation:
            return apology("confirmation not found")
        elif password != confirmation:
            return apology('Password did not match!')
        hash= generate_password_hash(password)
        try:
            db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hash)
            return redirect('/')
        except:
            return apology('username has already been registered')

    else:
        return render_template("register.html")




@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method=="POST":
        user_id= session["user_id"]
        symbol= request.form.get("symbol")
        if not symbol:
            return apology("Symbol is required!")
        shares=int(request.form.get("shares"))
        if shares<=0:
            return apology("Shares must be positive number")

        item_name= lookup(symbol)["name"]
        item_price= lookup(symbol)["price"]
        price= item_price * shares
        shares_owned= db.execute("SELECT shares FROM transactions WHERE user_id= ? AND symbol=?",user_id, symbol)[0]["shares"]
        if shares>shares_owned:
            return apology("No enough shares!")

        current_cash= db.execute("SELECT cash FROM users WHERE id= ?",user_id)[0]["cash"]

        db.execute("UPDATE users SET cash=? WHERE id=? ", current_cash + price, user_id )

        db.execute("INSERT INTO transactions(user_id, name, shares, price, type, symbol) VALUES(?, ?, ?, ?, ?, ?)",user_id, item_name, -shares, item_price, 'sell', symbol)
        return redirect('/')

    else:
        user_id= session["user_id"]
        symbols= db.execute("SELECT symbol FROM transactions WHERE user_id=? GROUP BY symbol",user_id)
        return render_template("sell.html", symbols=symbols)


@app.route('/pchange', methods=["POST", "GET"])
@login_required
def changep():
    # to change the password
    if request.method == "POST":
        username=request.form.get("username")
        password=request.form.get("password")
        newpassword=request.form.get("newpassword")
        confirmation=request.form.get("confirmation")

        if not username:
            return apology("Username required!")
        elif not password:
            return apology("Password required!")

        if newpassword != confirmation:
            return apology("Confirmation didnt match!")



        user = db.execute("SELECT hash FROM users WHERE username=?", username)

        if not user:
            return apology("Invalid Username")
        newhash=user[0]["hash"]
        if not check_password_hash(newhash, password):
            return apology("Wrong password")

        hash1= generate_password_hash(newpassword)
        db.execute("UPDATE users SET hash=? WHERE username=?", hash1, username)
        return redirect('/logout')
    else:
        return render_template("pchange.html")


