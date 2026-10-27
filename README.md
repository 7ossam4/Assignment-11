# Anonymous Chat API

Run: `npm install && npm start` (port 3000) — test: `npm test`
Env: JWT_SECRET, PORT, DB_FILE, and optionally SMTP_HOST/SMTP_PORT/SMTP_USER/SMTP_PASS/SMTP_FROM
(without SMTP, OTP emails are printed in the server console).

| Method | Endpoint | Who | Description |
|---|---|---|---|
| POST | /auth/register | public | name, email, password |
| POST | /auth/login | public | 5 wrong passwords = 5 min ban (429). If 2FA on -> sends OTP |
| POST | /auth/login/confirm | public | email, otp -> tokens |
| POST | /auth/2fa/enable | logged in | sends OTP |
| POST | /auth/2fa/verify | logged in | otp -> enables 2FA |
| POST | /messages | logged in | receiverId, content (anonymous) |
| GET | /messages/received | receiver | inbox (sender hidden until accepted) |
| POST | /messages/:id/request-identity | receiver | creates pending request |
| GET | /requests | sender | requests on my messages |
| PATCH | /requests/:id | sender | {action: "accept"|"reject"}; accept creates conversation |
| POST | /conversations/:id/messages | the 2 users | send message |
| GET | /conversations/:id/messages | the 2 users | get messages |

Send the access token as `Authorization: Bearer <token>`.
"# Assignment-11" 
