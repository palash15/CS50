import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd
app.jinja_env.globals.update(usd=usd)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    rows = db.execute("SELECT * FROM transactions WHERE userid=:userid", userid=session["user_id"])
    rows_2 = db.execute("SELECT cash FROM users WHERE id=:userid", userid=session["user_id"])
    cash = rows_2[0]["cash"]
    stocks = set([row["symbol"] for row in rows])
    fields = []
    tot_val = 0

    for stock in stocks:
        value = 0
        shares = 0
        curr_price = lookup(stock)["price"]
        for row in rows:
            if row["symbol"] == stock and row["action"] == "buy":
                shares += row["shares"]

            elif row["symbol"] == stock and row["action"] == "sell":
                shares -= row["shares"]

        value = shares*curr_price
        tot_val += value

        if shares != 0:
            fields.append([stock, shares, curr_price, value])

    return render_template("index.html", fields=fields, cash=cash, total=tot_val+cash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        quote = lookup(request.form.get("symbol"))

        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("must be a number")

        if shares < 0:
            return apology("please enter a positive number")

        elif quote == None:
            return apology("invalid ticker symbol")

        price = quote["price"]
        value = price*shares
        now = datetime.now()

        rows = db.execute("SELECT cash FROM users WHERE id=:userid", userid=session["user_id"])
        bal = rows[0]["cash"]

        if bal < value:
            return apology("insufficient funds")

        db.execute("UPDATE users SET cash = cash - :value WHERE id = :userid", value=value,\
                    userid=session["user_id"])

        db.execute("INSERT INTO transactions (userid, symbol, price, shares, value, dtime, action) \
                    VALUES (:userid, :symbol, :price, :shares, :value, :dtime, :action)", \
                    userid=session["user_id"], symbol=request.form.get("symbol"), price=price, shares=shares, \
                    value=value, dtime=now, action="buy")

        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""

    u_name = request.args.get("username")

    rows = db.execute("SELECT username FROM users")
    u_names = [row["username"] for row in rows]

    if u_name not in u_names and len(u_name) > 0:
        return jsonify(True)

    else:
        return jsonify(False)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    rows = db.execute("SELECT * from transactions WHERE userid=:userid", userid=session["user_id"])
    return render_template("history.html", rows=rows)


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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

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
        if not request.form.get("symbol"):
            return apology("must provide symbol")

        quote = lookup(request.form.get("symbol"))

        if quote is None:
            return apology("cannot find symbol")

        return render_template("quoted.html", quote=quote)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        name = request.form.get("username")
        pasw = request.form.get("password")
        pasw_c = request.form.get("confirmation")

        if not name:
            return apology("must provide username")

        elif not pasw:
            return apology("must provide password")

        elif not pasw_c:
            return apology("must provide confirmation password")

        elif pasw != pasw_c:
            return apology("passwords do not match")

        hash = generate_password_hash(pasw)
        rows = db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", username=name, hash=hash)

        if not rows:
            return apology("username already exists!")
        else:
            return apology("registration complete", 200)

        session["user_id"] = rows[0]["id"]
        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares", type=int)
        quote = lookup(symbol)
        price = quote["price"]
        value = price*shares
        now = datetime.now()

        rows = db.execute("SELECT * from transactions WHERE (userid=:userid AND symbol=:symbol)", \
                userid=session["user_id"], symbol=symbol)

        shares_b = sum([row["shares"] for row in rows if row["action"] == "buy"])
        shares_s = sum([row["shares"] for row in rows if row["action"] == "sell"])
        rem_shares = shares_b - shares_s

        if not symbol:
            return apology("please enter symbol")

        elif rows is None or rem_shares == 0:
            return apology("you do not own this stock")

        elif quote is None:
            return apology("cannot find symbol")

        elif shares <= 0:
            return apology("please enter a positive number")

        elif shares > rem_shares:
            return apology("you do not have that many shares")

        db.execute("UPDATE users SET cash = cash + :value WHERE id = :userid", value=value, \
                    userid=session["user_id"])

        db.execute("INSERT into transactions (userid, symbol, price, shares, value, dtime, action) \
                    VALUES (:userid, :symbol, :price, :shares, :value, :dtime, :action)", \
                    userid=session["user_id"], symbol=symbol, price=price, shares=shares, \
                    value=value, dtime=now, action="sell")

        return redirect("/")

    else:
        avail_stocks = db.execute("SELECT symbol, SUM(shares) as total_shares FROM transactions \
                                        WHERE userid = :userid GROUP BY symbol", userid=session["user_id"])
        return render_template("sell.html", avail_stocks=avail_stocks)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
