import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Ensure environment variable is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")

# Configure application
app = Flask(__name__)

# this is to ensure that save the recent sale activity for index page
last_sale = {'sym': 0, 'num': 0, 'cost': 0, 'total': 0}

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
    # This is to get all the values of the table sales for display in index
    final_table = db.execute("SELECT * FROM sales WHERE id=:userid", userid=session["user_id"])
    values = [0 for i in range(len(final_table))]
    key = [0 for i in range(len(final_table))]
    st2 = [0 for i in range(len(final_table) * 4)]

    for i in range(len(final_table)):
        st = final_table[i]
        key[i], values[i] = zip(*st.items())

    counter = 0
    # This variable calculates the sum of all the shares bought
    share_sum = 0
    for j in range(len(values)):
        st2[counter] = values[j][1]
        st2[counter + 1] = values[j][2]
        st2[counter + 2] = usd(values[j][3])
        st2[counter + 3] = usd(values[j][4])
        share_sum += values[j][4]
        counter += 4

    # This is to get the balance on the user from the user table
    user_balance = db.execute("SELECT cash FROM users WHERE id=:userid", userid=session["user_id"])
    balance = user_balance[0]['cash']
    balance = usd(balance)
    share_sum = usd(share_sum)
    global last_sale
    activity = [None, None, None, None]
    activity[0] = last_sale['sym']
    activity[1] = last_sale['num']
    activity[2] = last_sale['cost']
    activity[3] = last_sale['total']

    # This returns to index all the variables to later use in jinja2
    return render_template("index.html", balance=balance, st2=st2, share_sum=share_sum, activity=activity)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":

        sym = request.form.get("symbol")
        sym = sym.upper()
        quan = request.form.get("shares")

        # If the user inputs anything other than digits, this returns error
        if not quan.isdigit():
            return apology("Enter a valid number", 400)
        quan = float(quan)
        if sym.startswith("^"):
            return apology("Stock symbol cannot start with caret(^)", 400)
        if ',' in sym:
            return apology("Stock symbol cannot have comma(,)", 400)
        if quan < 1:
            return apology("Quantity has to be 1 or more", 400)
        if lookup(sym) == None:
            return("Stock does not exist", 400)

        price = lookup(sym)

        # This is stop Nonetype error if there is no price
        if price == None:
            return apology("Stock Does not exist", 2)
        stock_price = price["price"]
        total_price = round(stock_price * quan, 2)
        user_balance = db.execute("SELECT cash FROM users WHERE id=:userid", userid=session["user_id"])
        balance = user_balance[0]['cash']
        balance = round(balance, 2)
        if total_price > balance:
            return apology("Your Balance is too low", 400)

        db.execute("UPDATE users SET cash = cash - :total_price WHERE id = :userid",
                   total_price=total_price, userid=session["user_id"])
        balance = balance - total_price
        temp_row = db.execute("SELECT * FROM sales WHERE symbol=:sym", sym=sym)
        db.execute("INSERT INTO history (id, symbol, bought, sold, price) VALUES (:userid, :sym, :quan, 0, :stock_price)", userid=session["user_id"],
                   sym=sym, quan=quan, stock_price=stock_price)

        # This is to check if a share bought by user already exists or has to be added
        if len(temp_row) < 1:
            db.execute("INSERT INTO sales (id, symbol, shares, price, total) VALUES(:userid,:sym,:quan,:stock_price, :total_price)", userid=session["user_id"], sym=sym,
                       stock_price=stock_price, quan=quan, total_price=total_price)

        # If the share bought by user already exists, this updates the value instead of adding column
        elif len(temp_row) >= 1:
            db.execute("UPDATE sales SET shares = shares + :quan WHERE symbol = :sym AND id = :userid",
                       quan=quan, sym=sym, userid=session["user_id"])
            db.execute("UPDATE sales SET total = total + :total_price WHERE symbol = :sym AND id = :userid",
                       total_price=total_price, sym=sym, userid=session["user_id"])

        final_table = db.execute("SELECT * FROM sales WHERE id=:userid", userid=session["user_id"])
        values = [0 for i in range(len(final_table))]
        key = [0 for i in range(len(final_table))]
        st2 = [0 for i in range(len(final_table) * 4)]

        for i in range(len(final_table)):
            st = final_table[i]
            key[i], values[i] = zip(*st.items())

        counter = 0
        share_sum = 0
        for j in range(len(values)):
            st2[counter] = values[j][1]
            st2[counter + 1] = values[j][2]
            st2[counter + 2] = usd(values[j][3])
            st2[counter + 3] = usd(values[j][4])
            share_sum += values[j][4]
            counter += 4

        # The usd function formats all the input in the form of dollar currency
        share_sum = usd(share_sum)
        balance = usd(balance)
        return render_template("index.html", balance=balance, sym=sym, stock_price=stock_price, quan=quan, st2=st2, share_sum=share_sum)
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():

    # This is a new table that stores a history of all transactions made by a user
    final_table = db.execute("SELECT * FROM history WHERE id=:userid", userid=session["user_id"])
    values = [0 for i in range(len(final_table))]
    key = [0 for i in range(len(final_table))]
    st2 = [0 for i in range(len(final_table) * 4)]

    for i in range(len(final_table)):
        st = final_table[i]
        key[i], values[i] = zip(*st.items())

    counter = 0
    for j in range(len(values)):
        st2[counter] = values[j][1]
        st2[counter + 1] = values[j][2]
        st2[counter + 2] = values[j][3]
        st2[counter + 3] = values[j][4]
        counter += 4

    return render_template("history.html", st2=st2)


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
    if request.method == "GET":
        return render_template("quote.html")

    else:
        # Gets symbol from the website, and it is converted to uppercase
        sym = request.form.get("symbol")
        sym = sym.upper()
        # This is so that the user doesn't start a stock name with ^
        if sym.startswith("^"):
            return apology("Stock symbol cannot start with caret(^)", 400)
        # No commas in stock name
        if ',' in sym:
            return apology("Stock symbol cannot have comma(,)", 400)
        if lookup(sym) == None:
            return("Stock not found", 400)
        # The lookup function checks for the price of the stock
        stock_price = lookup(sym)
        stock_price = usd(stock_price["price"])
        return render_template("quoted.html", stock_price=stock_price, sym=sym)


@app.route("/register", methods=["GET", "POST"])
def register():
    session.clear()

    if request.method == "POST":
        # If username field is empty returns error
        if not request.form.get("username"):
            return apology("Must provide Username", 400)

        # If password is empty
        if not request.form.get("password"):
            return apology("Must Enter Password", 400)

        # If confirmation pass is empty
        if not request.form.get("confirmation"):
            return apology("Confirm your password", 400)

        # If the passwords don't match
        if not request.form.get("password") == request.form.get("confirmation"):
            return apology("The passwords do not match", 400)

        # To get username from user table
        temp_row = db.execute("SELECT username FROM users")
        u = 0
        user = [0 for x in range(len(temp_row))]
        user_name = [0 for x in range(len(temp_row))]
        for i in range(len(temp_row)):
            u = temp_row[i]
            x, user[i] = zip(*u.items())

        for i in range(len(temp_row)):
            user_name[i] = user[i][0]

        # If username entered already exists
        if request.form.get("username") in user_name:
            return apology("Username already exists", 400)

        db.execute("INSERT INTO users (id,username,hash) VALUES(NULL,:uname, :rpass)", uname=request.form.get("username"),
                   rpass=generate_password_hash(request.form.get("password")))

        return render_template("login.html")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    # This select list gets all the bought stock symbols to sell
    select_list = db.execute("SELECT symbol FROM sales WHERE id = :userid", userid=session["user_id"])
    values = [0 for i in range(len(select_list))]
    key = [0 for i in range(len(select_list))]
    st2 = [0 for i in range(len(select_list))]
    for i in range(len(select_list)):
        st = select_list[i]
        key[i], values[i] = zip(*st.items())
    for j in range(len(values)):
        st2[j] = values[j][0]

    if request.method == "POST":
        sym = request.form.get("symbol")
        sym = sym.upper()
        quan = int(request.form.get("shares"))
        share_balance = db.execute("SELECT shares FROM sales WHERE symbol=:sym AND id=:userid",
                                   sym=sym, userid=session["user_id"])

        # This is share Balance
        s_balance = share_balance[0]['shares']

        if quan < 1:
            return apology("Quantity has to be 1 or more", 400)

        stock_price = round(lookup(sym)["price"] * quan)

        # If user tries to sell more shares than he owns
        if quan > s_balance:
            return apology("You do not own that many shares to sell", 400)

        db.execute("INSERT INTO history (id, symbol, bought, sold, price) VALUES (:userid, :sym, 0, :quan, :stock_price)",
                   userid=session["user_id"], sym=sym, quan=quan, stock_price=stock_price)

        # If there are no more shares left of a stock, take it off the table
        if s_balance - quan == 0:
            db.execute("DELETE FROM sales WHERE symbol = :sym AND id = :userid", sym=sym, userid=session["user_id"])

        else:
            db.execute("UPDATE sales SET shares = shares - :quan WHERE symbol = :sym AND id = :userid",
                       quan=quan, sym=sym, userid=session["user_id"])

        db.execute("UPDATE users SET cash = cash + :stock_price WHERE id = :userid",
                   stock_price=stock_price, userid=session["user_id"])

        # Since last_sale is a global variable outside the function, it has to be init inside
        global last_sale
        # All the recent activity value for the index, last_sale is a dict here
        last_sale['sym'] = sym
        last_sale['num'] = quan
        last_sale['cost'] = usd(lookup(sym)["price"])
        last_sale['total'] = usd(stock_price)

        # Redirects to index page
        return redirect("/")

    else:
        return render_template("sell.html", st2=st2)


@app.route("/changepass", methods=["GET", "POST"])
@login_required
def changepass():

    if request.method == "POST":

        # This is to change user password
        oldpass = request.form.get("old_pass")
        newpass = request.form.get("new_pass")
        connewpass = request.form.get("conf_new_pass")
        password = db.execute("SELECT hash FROM users WHERE id =:userid", userid=session["user_id"])

        # The user's password is saved as a hash in table, this decrypts and checks it
        if not check_password_hash(password[0]['hash'], oldpass):
            return apology("Wrong Old password", 400)

        # Passwords don't match
        if not newpass == connewpass:
            return apology("Passwords don't match", 400)

        # If new and old pass is the same
        if oldpass == newpass:
            return apology("Old and New Passwords can't be the same", 400)

        # This generates a new hash key for the new pass and stores it
        newpass = generate_password_hash(newpass)
        db.execute("UPDATE users SET hash = :newpass", newpass=newpass)
        conf_str = "Password Changed"

        return render_template("changepass.html", conf_str=conf_str)

    else:
        return render_template("changepass.html")


def errorhandler(e):
    """Handle error"""
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
