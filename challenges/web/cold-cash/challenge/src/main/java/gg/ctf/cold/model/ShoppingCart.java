package gg.ctf.cold.model;

import java.util.ArrayList;
import java.util.List;

public class ShoppingCart {
    private List<CartItem> items;
    private int balance;
    private String couponCode;
    private static final String VALID_COUPON = "PALMER10";
    private static final int DISCOUNT_PERCENTAGE = 10;
    
    // FIX: Removed 'static' to make it an instance variable
    private boolean boughtFlag = false;

    public ShoppingCart() {
        this.items = new ArrayList<>();
        this.balance = 100; // Initial balance of $100
        this.couponCode = null;
    }

    // FIX: Added a public getter for the private 'boughtFlag' variable
    public boolean isBoughtFlag() {
        return this.boughtFlag;
    }

    public List<CartItem> getItems() {
        return items;
    }

    public void addItem(CartItem item) {
        items.add(item);
    }

    public void removeItem(int index) {
        if (index >= 0 && index < items.size()) {
            items.remove(index);
        }
    }

    public int getBalance() {
        return balance;
    }

    public void setBalance(int balance) {
        this.balance = balance;
    }

    public String getCouponCode() {
        return couponCode;
    }

    public void setCouponCode(String couponCode) {
        this.couponCode = couponCode;
    }

    public boolean isCouponValid() {
        return VALID_COUPON.equals(couponCode);
    }

    public int getDiscountPercentage() {
        return isCouponValid() ? DISCOUNT_PERCENTAGE : 0;
    }

    public int getTotal() {
        int total = items.stream()
                .mapToInt(CartItem::getTotal)
                .sum();
        total = Math.abs(total);
        
        if (isCouponValid()) {
            total = (int)(total * (100.0 - (double)DISCOUNT_PERCENTAGE) / 100.0);
        }
        
        return total;
    }

    public boolean canAfford() {
        return balance >= getTotal();
    }

    public void purchase() {
        if (canAfford()) {
            balance -= getTotal();
            boolean hasFlag = items.stream().anyMatch(item -> "flag".equals(item.getName()));
            if (hasFlag) {
                // This now sets the flag only for the current user's cart instance
                this.boughtFlag = true;
            }
            
            items.clear();
            couponCode = null;
        }
    }
}