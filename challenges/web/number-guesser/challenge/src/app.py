from flask import Flask, make_response, render_template, request
import base64
import os

app = Flask(__name__)

SECRET_NUMBER = 42

FLAG = b"ghctf{th3_r34l_pr1z3_w4snt_th3_numb3r}"
ENCODED_FLAG = base64.b64encode(FLAG).decode('utf-8')

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    This function handles the game logic and cookie setting.
    """
    message = "I'm thinking of a number between 1 and 100. Take a guess!"
    last_guess_value = ""

    if request.method == 'POST':
        try:
            guess = int(request.form.get('guess', ''))
            last_guess_value = str(guess) 

            if guess < SECRET_NUMBER:
                message = f"Too low! Your guess was {guess}."
            elif guess > SECRET_NUMBER:
                message = f"Too high! Your guess was {guess}."
            else:
                message = f"You got it! The number was {SECRET_NUMBER}. Congratulations!"
        except (ValueError, TypeError):
            message = "That doesn't look like a number. Please enter a number between 1 and 100."

    resp = make_response(render_template('index.html', message=message))

    resp.set_cookie('user_prefs', ENCODED_FLAG)

    if last_guess_value:
        resp.set_cookie('last_guess', last_guess_value)

    return resp

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)