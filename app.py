import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

from datetime import datetime, timezone

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
    acctInfo = {"symbol": [], "shares": [], "currPrice": [], "holdingVal": []}
    headers = ["Symbol", "Shares", "Price", "Holding Value"]
    heads = []

    userInfo = db.execute("SELECT ticker, shares FROM portfolio WHERE user_id = ?", session["user_id"])

    for i in range (len(userInfo)):
        acctInfo["symbol"].append(userInfo[i]["ticker"])
        acctInfo["shares"].append(userInfo[i]["shares"])
        acctInfo["currPrice"].append(lookup(acctInfo["symbol"][i])["price"])
        db.execute("UPDATE portfolio SET currPrice = ? WHERE user_id = ? AND ticker = ?", acctInfo["currPrice"][i], session["user_id"], acctInfo["symbol"][i])
        acctInfo["holdingVal"].append(acctInfo["currPrice"][i] * int(acctInfo["shares"][i]))

    curr_cash = float(db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"])

    grand_total = curr_cash + sum(acctInfo["holdingVal"])
    db.execute("UPDATE portfolio SET total = ? WHERE user_id = ?", grand_total, session["user_id"])
    for key in acctInfo:
        heads.append(key)

    return render_template("portfolio.html", headers = headers, keys = heads, portfolio = acctInfo, length = len(userInfo), total = float("{:.2f}".format(grand_total)), balance = float("{:.2f}".format(curr_cash)))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        price = lookup(symbol)
        tickList = []

        # validating input of symbol and shares
        if not symbol:
            return apology("Enter a symbol", 400)
        elif price is None:
            return apology("Enter a valid ticker", 400)
        elif not shares:
            return apology("Enter the number of shares", 400)
        else:
            try:
                num_shares = int(shares)
                if num_shares < 1:
                    return apology("number of shares must be a positive integer", 400)
            except ValueError:
                return apology("number of shares must be a positive integer", 400)

        # if input is valid
        total_cost = float(price["price"] * int(shares))
        curr_cash = float(db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"])

        if curr_cash < total_cost:
            return apology("Sorry, not enough balance to complete the transaction", 400)

        curr_balance = curr_cash - total_cost
        transaction_type = "buy"
        now = datetime.now(timezone.utc)
        date = now.strftime("%d/%m/%Y")
        time = now.strftime("%H:%M:%S")

        db.execute("UPDATE users SET cash = ? WHERE id = ?", float("{:.2f}".format(curr_balance)), session["user_id"])
        db.execute("INSERT INTO transaction_history (user_id, symbol, price, shares, total, type, date, time) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", session["user_id"], symbol, "{:.2f}".format(price["price"]), shares, "{:.2f}".format(total_cost), transaction_type, date, time)

        symbols = db.execute("SELECT ticker FROM portfolio WHERE user_id = ?", session["user_id"])
        for sym in symbols:
            tickList.append(str(sym["ticker"]))

        if symbol not in tickList:
            db.execute("INSERT INTO portfolio (user_id, ticker, shares) VALUES (?, ?, ?)", session["user_id"], symbol, shares)
        else:
            db.execute("UPDATE portfolio SET shares = shares + ? WHERE user_id = ? AND ticker = ?", shares, session["user_id"], symbol)

        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    histInfo = {"Symbol": [], "Price": [], "Shares": [], "Total": [], "Type": [], "Date": [], "Time": []}
    heads = []

    history = db.execute("SELECT symbol, price, shares, total, type, date, time FROM transaction_history WHERE user_id = ?", session["user_id"])

    for key in histInfo:
        heads.append(key)

    length = len(history)

    for i in range(length):
        histInfo["Symbol"].append(history[i]["symbol"])
        histInfo["Price"].append(history[i]["price"])
        histInfo["Shares"].append(history[i]["shares"])
        histInfo["Total"].append(history[i]["total"])
        histInfo["Type"].append(history[i]["type"])
        histInfo["Date"].append(history[i]["date"])
        histInfo["Time"].append(history[i]["time"])

    return render_template("history.html", headers = histInfo, histInfo = histInfo, length = length, keys = heads)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
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
    if request.method == "POST":
        tick = request.form.get("symbol")
        vals = lookup(tick)
        if vals is None:
            return apology("Enter a valid ticker", 400)
        return render_template("quoted.html", tick=vals["symbol"], name=vals["name"], price=usd(vals["price"]))
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # validates username and if valid, stores it in newUsername
        if not request.form.get("username"):
            return apology("must provide username", 400)
        else:
            rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
            if len(rows) >= 1:
                return apology("username already exists", 400)
            else:
                newUsername = request.form.get("username")

        # validates password and if valid, stores it in newPassword
        if not request.form.get("password"):
            return apology("must provide a password", 400)
        elif not request.form.get("confirmation"):
            return apology("must confirm the password", 400)
        elif not request.form.get("password") == request.form.get("confirmation"):
            return apology("passwords do not match", 400)
        else:
            passHash = generate_password_hash(request.form.get("confirmation"))

        # registers the username and associated password into the database
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", newUsername, passHash)

        # redirect the user to login page
        return redirect("/login")

    else:
        return render_template("register.html")

@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Change password"""
    if request.method == "POST":
        # validates the password
        passWord = request.form.get("password")
        confirm = request.form.get("confirmation")

        if not passWord:
            return apology("Enter a password", 400)
        if not confirm:
            return apology("Confirm the password", 400)
        if not confirm == passWord:
            return apology("The passwords do not match", 400)

        passHash = generate_password_hash(passWord)

        db.execute("UPDATE users SET hash = ? WHERE id = ?", passHash, session["user_id"])

        return redirect("/")

    else:
        return render_template("changePass.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":

        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        price = lookup(symbol)
        checkSym = False
        checkShares = False
        remShares = 200

        owned = db.execute("SELECT ticker, shares FROM portfolio where user_id = ?", session["user_id"])

        # validating input of symbol and shares
        if not symbol:
            return apology("Enter a symbol", 400)
        elif price is None:
            return apology("Enter a valid ticker", 400)
        elif not shares:
            return apology("Enter the number of shares", 400)
        else:
            try:
                num_shares = int(shares)
                if num_shares < 1:
                    return apology("number of shares must be a positive integer", 400)
            except ValueError:
                return apology("number of shares must be a positive integer", 400)

        # checking if the user owns enough shares of the company to sell them
        for i in range(len(owned)):
            if symbol == owned[i]["ticker"]:
                checkSym = True
            if checkSym:
                if int(shares) <= int(owned[i]["shares"]):
                    checkShares = True
                    remShares = int(owned[i]["shares"])- int(shares)
        if not checkShares:
            return apology("You do not own wnough shares of this company to sell the amount you want", 400)


        # if input is valid
        total_rev = float(price["price"] * int(shares))
        transaction_type = "sell"
        now = datetime.now(timezone.utc)
        date = now.strftime("%d/%m/%Y")
        time = now.strftime("%H:%M:%S")

        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", total_rev, session["user_id"])
        db.execute("INSERT INTO transaction_history (user_id, symbol, price, shares, total, type, date, time) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", session["user_id"], symbol, price["price"], shares, total_rev, transaction_type, date, time)
        if remShares > 0:
            db.execute("UPDATE portfolio SET shares = ? WHERE user_id = ? AND ticker = ?", remShares, session["user_id"], symbol)
        elif remShares == 0:
            db.execute("DELETE FROM portfolio WHERE user_id = ? AND ticker = ?", session["user_id"], symbol)

        return redirect("/")

    else:
        return render_template("sell.html")