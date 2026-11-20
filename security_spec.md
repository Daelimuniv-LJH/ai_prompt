# Security Specification: 이종혁의 세상 (Production Hardened Rules)

## 1. Data Invariants
- Only the `/prompts/{promptId}` collection is accessible; all other collections and paths are completely denied for both reads and writes.
- Every document in `/prompts/{promptId}` must have a valid document ID (`^[a-zA-Z0-9_\\-]+$`, <= 128 chars).
- Every document in `/prompts/{promptId}` must contain strictly and only the 4 required keys: `title`, `category`, `content`, `createdAt`.
- `title` must be a non-empty string (`1 <= size <= 100`).
- `category` must be one of the 3 allowed categories: `'사진 합성'`, `'스타일 변환'`, `'캐릭터·포스터'`.
- `content` must be a non-empty string (`1 <= size <= 10000`), supporting long multi-line prompts over 1,000 characters.
- `createdAt` must equal `request.time` on `create`, and must remain immutable (`incoming().createdAt == existing().createdAt`) on `update`.
- Reads (`get`, `list`) on `prompts` are publicly allowed so guests can browse, search, filter, and copy prompts without logging in.
- Writes (`create`, `update`, `delete`) on `prompts` are strictly restricted to the verified admin account (`whdgur0839@gmail.com`).

## 2. Adversarial Payloads Checked
1. Unauthenticated `create` / `update` / `delete` on `/prompts` -> Rejected by `isAdmin()`.
2. Authenticated non-admin user `create` / `update` / `delete` -> Rejected by `isAdmin()`.
3. Unverified email spoofing (`email == 'whdgur0839@gmail.com'`, `email_verified == false`) -> Rejected by `email_verified == true`.
4. Read or write on any collection other than `/prompts` (e.g., `/users`, `/test`, `/admin`) -> Rejected by global default-deny catch-all.
5. Shadow field injection -> Rejected by `keys().hasOnly(...)`.
6. Missing required field -> Rejected by `keys().hasAll(...)`.
7. Invalid category -> Rejected by `category in [...]`.
8. Title > 100 chars or empty -> Rejected by `title.size()`.
9. Content > 10000 chars or empty -> Rejected by `content.size()`.
10. Client-spoofed `createdAt` on create -> Rejected by `createdAt == request.time`.
11. Mutating `createdAt` during update -> Rejected by `incoming().createdAt == existing().createdAt`.
12. Malformed document ID -> Rejected by `isValidId(promptId)`.
