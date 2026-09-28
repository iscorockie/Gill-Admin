# Gill Admin & Staff API

This is the private PHP/MySQL API intended to back the Vercel portal at `https://admin.gill.ac.ug`. It keeps staff accounts, announcements, and requests out of the public GitHub content repository. The API is deliberately separate from the static website and **is not live until deployed and configured on Crystal/Webuzo**.

## What it provides

- Password-based accounts with server-side `password_hash()` verification and roles (`admin`, `staff`).
- Admin-issued, single-use email invitations for staff; password reset links; SMTP via PHPMailer.
- Session cookies (`Secure`, `HttpOnly`, `SameSite=Lax`), origin checks, CSRF tokens, login throttling, and prepared SQL statements.
- Staff directory, announcements, and private staff requests (staff can see their own requests; admins can see all).
- SQL audit events for key administrative actions.

The mailbox `info@gill.ac.ug` is used only as a sender/admin contact. It is not used as the portal password, and mailbox credentials must never be reused as portal credentials.

## Webuzo setup (do not enable remote MySQL)

1. In Webuzo, use **Database → Database Wizard** to create a dedicated database and database user. Grant that user access only to this database. For an API hosted on the same Crystal server, use `localhost`; **Remote MySQL Access is not needed**.
2. Import `schema.sql` into the new database using phpMyAdmin.
3. Create an API subdomain (recommended: `api.gill.ac.ug`) in Webuzo. Its document root should point to this folder's `public/` directory. Ensure the subdomain has HTTPS before allowing logins.
4. If DNS is managed at Vercel, create the API host record there using the Crystal server IP shown in Webuzo. Do not alter existing mail or website records. Verify the new API subdomain reaches the Crystal server before continuing.
5. Copy `config.example.php` to `config.php` in the backend directory (outside `public/`). Fill in the DB details and the SMTP host/port/encryption shown under **Webuzo → Email → Email Account → Configure Mail Client**. Keep this file private and set restrictive permissions.
6. Install dependencies from this directory (`composer install --no-dev --optimize-autoloader`) so PHPMailer is available. Do not place `config.php` or `vendor/` under the public document root if Webuzo allows a separate app directory.
7. Run `php bin/create-admin.php` from a shell/terminal to create the first portal administrator. Use a new portal-only password. If SSH/terminal is unavailable, ask Crystal support for a private CLI run; do not create an internet-accessible installer endpoint.
8. Remove `bin/create-admin.php` from the live server after bootstrap. Never publish private DB or SMTP credentials.

Use the SMTP settings Webuzo provides rather than guessing. The example defaults are placeholders and may not match the account's actual SMTP configuration.

## API contract

Base URL: `https://api.gill.ac.ug`

- `GET /health`
- `POST /auth/login` `{ "email", "password" }`
- `GET /auth/me` — returns the user and session CSRF token
- `POST /auth/logout` — requires `X-CSRF-Token`
- `POST /auth/forgot-password` `{ "email" }` — always returns a generic response
- `POST /auth/reset-password` `{ "email", "token", "password" }`
- `POST /auth/accept-invite` `{ "email", "token", "password" }`
- `GET /staff` — authenticated directory
- `POST /staff/invitations` — admin only; `{ "email", "full_name", "department", "job_title", "phone" }`
- `PATCH /staff/{id}` / `DELETE /staff/{id}` — admin only
- `GET /announcements`; `POST /announcements`; `PATCH /announcements/{id}`; `DELETE /announcements/{id}`
- `GET /requests`; `POST /requests`; `PATCH /requests/{id}` — admins may review/close; staff may only see their own and submit new requests

For authenticated `POST`, `PATCH`, and `DELETE` calls, send the `csrf_token` returned by `/auth/me` as `X-CSRF-Token`, use `credentials: 'include'`, and send JSON. CORS is limited to the exact production frontend origin in `config.php`.

## Before production

- This code has not been deployed to Crystal and cannot be tested against its database/SMTP account from this repository. Configure it on a staging hostname first.
- Connect the frontend only after the API health check, HTTPS, mail sending, invitation, login, CSRF, role permissions, request privacy, and password reset have been tested.
- The existing static dashboard still contains its old client-side login and browser-held GitHub publishing token flow. Do not treat that old login as security for staff data; the frontend must be switched to this API before staff records are used.
