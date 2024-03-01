import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///sustainWebsite.db")

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
def index():
    # Pass the data to the HTML template for rendering.
    return render_template("home.html")


@app.route("/actions")
def actions():
    return render_template("actions.html")

@app.route("/donations")
def donations():
    # Pass the data to the HTML template for rendering.
    return render_template("donations.html")


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
            "SELECT * FROM Users WHERE username = ?", request.form.get("username")
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

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        # save username and passwords
        username = request.form.get("username")
        existing_user = db.execute("SELECT * FROM Users WHERE username = ?", username)

        # if the user exists then send error message
        if existing_user:
            return apology("Username already taken", 400)
        else:
            # get all data from the form
            password = request.form.get("password")
            lastname = request.form.get("lastname")
            firstname = request.form.get("firstname")
            confirmation = request.form.get("confirmation")

            # ensure data was submitted
            if not lastname or not firstname:
                return apology("must provide all name data", 400)
            # Ensure password and confirmation were submitted
            elif not password or not confirmation:
                return apology("must provide password", 400)
            # Ensure password and confirmation are the same
            elif password != confirmation:
                return apology("passwords don't match", 400)
            else:
                # get password hash
                password_hash = generate_password_hash(password)
                # save into the database
                db.execute(
                    "INSERT INTO Users (username, firstname, lastname, hash) VALUES (?, ?, ?, ?)",
                    username,
                    firstname,
                    lastname,
                    password_hash,
                )
                return redirect("/")
    else:
        return render_template("signup.html")
