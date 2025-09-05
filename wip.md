Flow:

- User creates a room with create room button
- We load the room page, required buttons / interaction:
  - Start draafting
  -

Misc Things:

- Add heartbeat / timeout to websocket connection
- https://stackoverflow.com/questions/60098005/fastapi-starlette-get-client-real-ip

Rejoin Flow (user is already in a room):

- Refresh page / join room / create room:
  -> Returns the room you are already in

Auth:

- Use authorization header with bearer token
- Replace JWT secret with env variable
