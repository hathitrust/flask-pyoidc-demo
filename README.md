# Example of OpenID Connect with Flask

This includes a simple onboarding/registration workflow.

## Setup

```bash
pip install -r requirements.txt
python app.py
```

## Registration Example

* Go to 127.0.0.1:5555/onboard?email=somebody@default.invalid
* This returns a 'registration link'
* Visit the registration link and log in
* That email is now associated with the logged-in user identity info

## Caveats

Needless to say, this is a toy example that should not be used directly in
production. To be production-ready, it should at the least:

* use a real back-end for user information
* encrypt the registration keys in that back end
