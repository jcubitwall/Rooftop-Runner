# Rooftop Runner

A pixel-art rooftop runner game in a single HTML file. Open `index.html` in a browser to play.

## Player accounts

Kids can sign in with a name and password, and the game remembers the furthest level they've reached (and their best distance) on any device. Guests can still play without an account; their progress stays on that device only.

Accounts are stored by a small Cloudflare Worker in `server/worker.js`, using one Workers KV namespace bound as `ACCOUNTS`. Passwords are stored only as salted hashes. Five wrong passwords lock a name for 10 minutes.

The sign-in screen only appears once `API_URL` near the "player accounts" section of `index.html` is set to the Worker's address.

To reset a forgotten password, delete that player's `user:<name>` entry in the KV namespace in the Cloudflare dashboard. They can then make the name again, but they start from level 1.
