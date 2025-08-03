# Cold Cash: Challenge Writeup

**Goal:** Use bugs to turn your \$100 into billions and buy the `flag` item.

---

## 1. Get Admin Access

The endpoint `/admin/add-product` has a bug: it does `user.admin = true` instead of checking `user.admin == true`. That means *any* POST to this URL makes you an admin.

**Quick methods:**

* **Browser console (`fetch`)**

  ```js
  fetch('/admin/add-product', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'name=test&price=1&description=test'
  });
  // Reload to see ADMIN badge
  ```

* **Command line (`curl`)**

  ```bash
  curl -X POST http://localhost:12301/admin/add-product \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Cookie: JSESSIONID=<your_session_id>" \
    -d "name=test&price=1&description=test"
  ```

  *(Replace `<your_session_id>` with your actual session cookie to avoid errors.)*

---

## 2. Cause Integer Overflow

The application calculates the sum of all item prices in a 32-bit signed integer. After summing, it calls `Math.abs(total)` to ensure the value is positive. However, Java’s `Math.abs()` has a known edge case:

* The minimum 32-bit signed integer is **-2,147,483,648**.
* There is no positive counterpart for this value (because +2,147,483,648 overflows the 32-bit range).
* Therefore, `Math.abs(-2_147_483_648)` **returns** `-2_147_483_648` instead of flipping the sign.

To trigger this:

1. Make the raw sum equal exactly **2,147,483,648**.
2. This sum overflows in 32-bit arithmetic to **-2,147,483,648**.
3. `Math.abs(-2_147_483_648)` still yields **-2,147,483,648**, giving a negative cart total.

---

## 3. All together

1. **Become admin** using Step 1.
2. **Add a product** named `maxint` with `price = 2147483647` (the maximum 32-bit signed integer).
3. **Add a \$1 item** to your cart. Internally:

   * Raw sum: `2147483647 + 1 = 2147483648`
   * 32-bit overflow: `2147483648 → -2147483648`
   * `Math.abs(-2147483648)` still yields **-2147483648** (negative total).
4. **Apply the coupon** `PALMER10`. This coupon subtracts a percentage (e.g., 10%) from the negative total, resulting in a new value like `-1932735283` (still negative). When `Math.abs()` is called again:

   * `Math.abs(-1,932,735,283)` converts the negative overflowed amount into a positive **1,932,735,383**.
5. **Purchase:** Because the cart total is now interpreted as a massive positive credit, your balance increases by billions.
6. **Buy the flag**: Clear the cart, add the `flag` item (costly but affordable now), and complete the challenge.

